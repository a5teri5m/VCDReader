import os
import re

_vcd_header_keywords = ['date', 'version', 'timescale', 'scope', 'var', 'upscope', 'comment', 'enddefinitions']
_vcd_header_end_keywords = [k + '_end' for k in _vcd_header_keywords]

class VCDReader(object):

    def __init__(self, file):
        self.file = file
        self.id2signal = dict()
        self.top = _vcd_object('top', 'top', None)
        self.header = {'date':'', 'version':'', 'timescale':'', 'comment':''}
        self._parse_header()

    def _parse_header(self):
        with open(self.file) as fp:
            stat = []
            current_scope = self.top
            flags = {k:False for k in _vcd_header_keywords}
            for line in fp:
                line = line.strip()
                env = _cmdstat(line, stat)
                if env in _vcd_header_keywords:
                    flags[env] = True
                elif env in _vcd_header_end_keywords:
                    env = env.replace('_end', '')
                    if not flags[env]:
                        if env in self.header:
                            self.header[env] += _del_keyword(line, env)
                        elif env == 'scope':
                            scope = _parse_scope(_del_keyword(line, 'scope'))
                            current_scope = current_scope.add_child(scope['name'], scope['type'])
                        elif env == 'var':
                            var = _parse_var(_del_keyword(line, 'var'))
                            signal = current_scope.add_signal(var['id'], var['name'], var['width'])
                            self.id2signal.update({var['id']:signal})
                        elif env == 'upscope':
                            current_scope = current_scope.parent
                        elif env == 'enddefinitions':
                            break
                    flags[env] = False
                else:
                    if any([i for i in flags.values()]):
                        env = [k for k, v in flags.items() if v][0]
                        if  env in self.header:
                            self.header[env] += line if not self.header[env] else ('\n' + line)
                        elif env == 'scope':
                            scope = _parse_scope(_del_keyword(line, 'scope'))
                            current_scope = current_scope.add_child(scope['name'], scope['type'])
                        elif env == 'var':
                            var = _parse_var(_del_keyword(line, '$var'))
                            signal = current_scope.add_signal(var['id'], var['name'], var['width'])
                            self.id2signal.update({var['id']:signal})
                    else:
                        raise ValueError(line)

    def tree(self, obj=None, depth=0):
        ret = ''
        for obj in self.get_objects(obj):
            ret += '[{}] {}\n'.format(_short_type(obj), obj.name)
            ret += self._tree(obj.children, depth, 0, ' ')
        return ret

    def _tree(self, vcd_obj, depth, cur, tab):
        ret = ''
        if depth == 0 or depth > cur:
            for i, o in enumerate(vcd_obj):
                last = True if i == (len(vcd_obj) - 1) else False
                ret += '{}{}── [{}] {}\n'.format(tab, '└' if last else '├', _short_type(o), o.name)
                if len(o.children):
                    ret += self._tree(o.children, depth, cur+1, tab + ('     ' if last else '|     '))
        return ret

    def get_values(self, sig=None, start=0, end=None, ip=False, return_id=False):
        sig = self.get_signals(sig)
        ret = {s.id:[] for s in sig}
        sval = {s.id:False for s in sig}
        with open(self.file) as fp:
            stat = []
            for line in fp:
                line = line.strip()
                env = _cmdstat(line, stat)
                if env == 'enddefinitions_end':
                    break
            time = 0
            in_dumpvars = False
            for line in fp:
                line = line.strip()
                env = _cmdstat(line, stat)
                if env == 'dumpvars':
                    in_dumpvars = True
                elif env == 'dumpvars_end':
                    in_dumpvars = False
                else:
                    if in_dumpvars:
                        var, val = _parse_values(line)
                        if var in ret:
                            if time < start:
                                sval[var] = val
                                continue
                            if end and end < time:
                                break
                            if ip and sval[var] != val and len(ret[var]) == 0:
                                ret[var].append((start, sval[var]))
                            ret[var].append((time, val))
                        else:
                            continue
                    else:
                        if line[0] == '#':
                            time = int(line[1:].strip())
                        else:
                            var, val = _parse_values(line)
                            if var in ret:
                                if time < start:
                                    sval[var] = val
                                    continue
                                if end and end < time:
                                    break
                                if ip and sval[var] != val and len(ret[var]) == 0:
                                    ret[var].append((start, sval[var]))
                                ret[var].append((time, val))
                            else:
                                continue
        if not return_id:
            ret = [val for val in ret.values()]
        return ret

    def get_signals(self, sig=None):
        ret = list()
        if sig is None:
            sig = self.get_objects(recursive=True)
            ret.extend(self.get_signals(sig))
        elif isinstance(sig, _vcd_signal):
            ret.extend([sig])
        elif isinstance(sig, _vcd_object):
            ret.extend(sig.signals)
        elif isinstance(sig, list):
            for s in sig:
                ret.extend(self.get_signals(s))
        elif isinstance(sig, str):
            path = sig.split('.')
            if len(path) != 1:
                sig = path[-1]
                path = '.'.join(path[0:-1])
                obj = self.get_objects(path)[0]
                if sig == '*':
                    ret.extend(obj.signals)
                else:
                    if sig in obj.name2child:
                        ret.extend(self.get_signals(obj.name2child[sig]))
                    else:
                        ret.extend([obj.name2signal[sig]])
            else:
                obj = self.top
                if sig in obj.name2child:
                    ret.extend(self.get_signals(obj.name2child[sig]))
                else:
                    ret.extend([obj.name2signal[sig]])
        else:
            raise ValueError(ret)
        return ret

    def get_objects(self, obj=None, recursive=False):
        ret = list()
        if obj is None:
            ret.extend(self.get_objects(self.top.children[0]))
        elif isinstance(obj, _vcd_object):
            ret.extend([obj])
        elif isinstance(obj, list):
            for o in obj:
                ret.extend(self.get_objects(o))
        elif isinstance(obj, str):
            current = self.top
            for name in obj.split('.'):
                if name == '*':
                    current = current.children
                else:
                    current = current.name2child[name]
            if isinstance(current, _vcd_object):
                ret.extend([current])
            elif isinstance(current, list):
                ret.extend(self.get_objects(current))
        else:
            raise ValueError(obj)
        if recursive:
            for o in ret:
                if len(o.children):
                    ret.extend(self.get_objects(o.children, recursive))
        return ret

    def to_wavedrom(self, sig, period, start=0, end=None):
        if not isinstance(period, int):
            period = self.get_cycle(period, start, end)
        sig = self.get_signals(sig)
        data = self._get_wavedrom_data(sig, period, start, end)
        return {'signal': [self._generate_wavedrom(self.top.children[0], data, sig)]}

    def get_cycle(self, sig, start=0, end=None, repeat=5):
        sig = self.get_values(sig, start, end)
        if len(sig) != 1:
            raise ValueError(len(sig))
        chgs = sig[0]
        period = 0
        cnt = 0
        prev_time = 0
        prev_period = 0
        for time, val in chgs:
            period = time - prev_time
            prev_time = time 
            if period == prev_period:
                cnt += 1
                if cnt >= repeat:
                    return period
            else:
                prev_period = period
                cnt = 0
        raise RuntimeError(cnt, period)

    def _generate_wavedrom(self, current, data, sig):
        ret = []
        append_signals = [s for s in current.signals for s1 in sig if s is s1]
        if len(append_signals) != 0:
            ret.append(current.name)
            for s in append_signals:
                ret.append({'name':s.name, 'wave':data[s.id]['wave'], 'data':data[s.id]['data']})
        append_name = False
        for c in current.children:
            cwave = self._generate_wavedrom(c, data, sig)
            if len(cwave) != 0:
                if not append_name and len(append_signals) == 0:
                    ret.append(current.name)
                    append_name = True
                ret.append(cwave)
        return ret


    def _get_wavedrom_data(self, sig, period, start, end):
        values = self.get_values(sig, start, end, ip=True, return_id=True)
        ret = {s.id:{'wave':'', 'data':[]} for s in sig}
        time = start
        while True:
            empty = True
            for var, vals in values.items():
                if len(vals) == 0:
                    ret[var]['wave'] += '.'
                else:
                    s = self.id2signal[var]
                    tval = None
                    while True:
                        vtime, vval = vals[0]
                        if (time - period) < vtime <= time:
                            tval = vval
                            vals.pop(0)    
                        elif time < vtime:
                            break
                        if len(vals) == 0:
                            break
                    if tval is None:
                        ret[var]['wave'] += '.'
                    else:
                        w, d = _wave_encode(tval, s)
                        ret[var]['wave'] += w
                        if d:
                            ret[var]['data'].append(d)
                    empty = False
            time += period
            if end is not None and time > end:
                break
            if end is None and empty: 
                break
        return ret



class _vcd_object(object):
    
    def __init__(self, name, type, parent):
        self.name = name
        self.type = type
        self.parent = parent
        self.children = []
        self.signals = []
        self.name2child = dict()
        self.name2signal = dict()

    def add_child(self, name, type):
        child = _vcd_object(name, type, self)
        self.children.append(child)
        self.name2child.update({name:child})
        return child

    def add_signal(self, id, name, width):
        signal = _vcd_signal(id, name, width)
        self.signals.append(signal)
        self.name2signal.update({name:signal})
        return signal

def _short_type(obj):
    if obj.type == 'module':
        return 'm'
    else:
        raise ValueError(obj.type)

class _vcd_signal(object):

    def __init__(self, id, name, width):
        self.id = id
        self.name = name
        self.format = None
        self.width = width


def _del_keyword(line, key):
    return line.replace('${}'.format(key), '').replace('$end', '').lstrip()


def _cmdstat(line, stat):
    itr = re.finditer('\$\S+', line)
    if itr is None:
        env = stat[-1] if len(stat) else None
        return env
    else:
        env = None
        for i in itr:
            if i.group() == '$end':
                env = stat.pop(-1) + '_end'
            else:
                stat.append(i.group()[1:])
                env = i.group()[1:]
        return env


def _parse_scope(line):
    line = line.strip()
    val = line.split()
    if len(val) == 2:
        return {'type':val[0], 'name':val[1]}
    else:
        raise ValueError(line)


def _parse_var(line):
    line = line.strip()
    val = line.split()
    if len(val) == 4:
        return {'type':val[0], 'width':val[1], 'id':val[2], 'name':val[3]}
    elif len(val) == 5:
        return {'type':val[0], 'width':val[1], 'id':val[2], 'name':val[3]+val[4]}
    else:
        raise ValueError(line)


def _parse_values(line):
    m = re.match('(bx+|b\d+|\d+|x)\s*(\S+)', line)
    if m:
        return m.group(2), m.group(1)
    else:
        raise ValueError(line)


def _wave_encode(val, sig):
    mx = re.match('(b+)x+', val)
    mb = re.match('(b+)(0|1)', val) 
    if mx:
        return 'x', None
    if sig.format == 'clk':
        if mb:
            val = mb.gropu(2)
        val = 'h' if val == '1' else 'l'
        return val, None
    elif sig.format is None:
        if int(sig.width) == 1:
            if mb:
                return mb.group(2), None
            else:
                return val, None
        else:
            return '=', val
    raise ValueError(val, sig)


