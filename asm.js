
const selections = {
    'x16':  'x86 16bit',
    'x32':  'x86 32bit',
    'x64':  'x86 64bit',
    "x16att":  "x86 16bit ATT syntax",
    "x32att":  "x86 32bit ATT syntax",
    "x64att":  "x86 64bit ATT syntax",
    "x16nasm":  "x86 16bit NASM syntax",
    "x32nasm":  "x86 32bit NASM syntax",
    "x64nasm":  "x86 64bit NASM syntax",
    "arm":  "ARM - little endian",
    "armbe":  "ARM - big endian",
    "thumb":  "THUMB - little endian",
    "thumbbe":  "THUMB - big endian",
    "arm64":  "ARM64",
    "hexagon":  "Hexagon",
    "mips":  "Mips - little endian",
    "mipsbe":  "Mips - big endian",
    "mips64":  "Mips64 - little endian",
    "mips64be":  "Mips64 - bigendian endian",
    "sparc":  "Sparc - little endian",
    "sparcbe":  "Sparc - big endian",
    "sparc64be":  "Sparc64 - big endian",
    "systemz":  "System Z (S390x)",
    "evm":  "Ethereum VM"
}

class SelectInputType extends Component {

    constructor(props) {
        super(props);
        this.state = { mode: props.mode };
    }

    handleChange(e) {
        this.setState({ mode: e.target.value })
        this.props.onchange(e.target.value);
    }

    render(props, state) {
        var options = [];
        for (const [key, value] of Object.entries(selections)) {
            var prop = { 'value': key };
            if (key == this.state.mode) {
                prop['selected'] = true;
            }
            options.push(h('option', prop, value))
        }
        var sel = h('select', { 'onchange': this.handleChange.bind(this) }, options);
        return h('div', null,
            h('label', null, "Arch and syntax: "), sel);;
    }
}

class InputAssembly extends Component {
    constructor(props) {
        super(props);
        this.state = {
            mode: props.mode,
            text: props.initialtext
        }
    }

    handleArchChange(mode) {
        this.state.mode = mode;
        this.props.onchange(this.state.mode, this.state.text)
    }

    handleTextChange(e) {
        this.state.text = e.target.value;
        this.props.onchange(this.state.mode, e.target.value)
    }

    render(props, state) {
        return h('div', null,
            h(SelectInputType, {
                "mode": this.state.mode,
                "onchange": this.handleArchChange.bind(this)
            }),
            h('textarea', {
                "rows": 10,
                "cols": 60,
                "autocomplete": "off",
                "autocorrect": "off",
                "autocapitalize": "off",
                "spellcheck": false,
                'oninput': this.handleTextChange.bind(this)
            },
                state.text)
        );
    }
}

const output_options = {
    "cstr": "C String",
    "carr": "C Array",
    "pythonarr": "Python Array",
    "hex": "Hex"
}

class SelectOutputType extends Component {

    constructor(props) {
        super(props);
        this.state = { outmode: props.outmode }
    }

    handleChange(e) {
        this.setState({ outmode: e.target.value })
        this.props.onchange(e.target.value);
    }

    render(props, state) {
        var radios = [];
        for (const [key, value] of Object.entries(output_options)) {

            var radioopt = {
                type: 'radio',
                name: 'output',
                value: key,
                onchange: this.handleChange.bind(this)
            }

            if (key == state.outmode)
                radioopt['checked'] = true;

            var radio = h('input', radioopt);

            var label = h('label', { 'for': key }, value)
            radios.push(radio)
            radios.push(label)
        }
        return h('div', null, radios);
    }
}

class OutputAssembled extends Component {
    constructor(props) {
        super(props);
        this.state = { outmode: props.outmode }
    }

    handleChange(output) {
        this.props.onchange(output);
    }

    render(props, state) {
        return h('div', null,
            h(SelectOutputType, {
                "outmode": this.state.outmode,
                "onchange": this.handleChange.bind(this),
            }),
            h('textarea', {
                'rows': 10, 'cols': 60,
                "autocomplete": "off",
                "autocorrect": "off",
                "autocapitalize": "off",
                "spellcheck": false
            }, this.props.text));
    }
}

class AssemblerApp extends Component {

    constructor() {
        super();
        this.state = {
            mode: Object.entries(selections)[0][0],
            text: "nop",
            outmode: Object.entries(output_options)[0][0]
        }
        this.state.output = this.computeOutput(this.state.mode, this.state.text, this.state.outmode);
    }

    computeOutput(mode, text, outmode) {

        if (outmode == "hex") {
            return assemble_c(mode, text, 0x0);
        }

        if (text.indexOf(":")>0) { //has labels, can't parse per line
            var assembled = assemble_c(mode, text, 0x0);
            if (assembled.startsWith("ERROR")) {
                return assembled;
            }
            var res = "";

            if (outmode == "carr") {
                res += "unsigned char code[] = {\n";
            } else if (outmode == "pythonarr") {
                res += "code = [\n";
            }

            var resline = ''
            if (outmode == "cstr") {
                resline = '"' + "\\x" + assembled.replace(/ /g, "\\x") + '"';
            } else {
                resline = "0x" + assembled.replace(/ /g, ", 0x");
            }

            res += resline;

            if (outmode == "carr") {
                res += "}";
            } else if (outmode == "pythonarr") {
                res += "]";
            }
            return res;
    
        }

        var lines = text.split("\n")
        var res = "";

        if (outmode == "carr") {
            res += "unsigned char code[] = {\n";
        } else if (outmode == "pythonarr") {
            res += "code = [\n";
        }

        var comment = " // ";
        if (outmode == "pythonarr")
            comment = " # ";

        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line == "")
                continue;
            var tmp = assemble_c(mode, line, 0x0);
            if (tmp == "")
                continue;
            if (tmp.startsWith("ERROR")) {
                res += "\n\n ERROR starting from line " + (i + 1) + ": '" + line + "'\n\n"
                res += tmp + "\n"
                break;
            }
            var resline = ''
            if (outmode == "cstr") {
                resline = "\\x" + tmp.replace(/ /g, "\\x");
            } else {
                resline = "0x" + tmp.replace(/ /g, ", 0x");
            }

            if (outmode == "cstr") {
                res += "\"";
                res += resline
                res += "\"" + comment + line;
            } else { //c or python array
                res += "    " + resline
                if (i < lines.length - 1)
                    res += ","
                res += comment + line
            }
            res += "\n"
        }

        if (outmode == "carr") {
            res += "}";
        } else if (outmode == "pythonarr") {
            res += "]";
        }
        return res;
    }

    handleChange(mode, text) {
        if (text == null)
            return;
        this.setState({ mode: mode, text: text });
        var result = this.computeOutput(mode, text, this.state.outmode);
        this.setState({ output: result });
    }

    handleOutputChange(mode) {
        this.setState({ outmode: mode });
        var result = this.computeOutput(this.state.mode, this.state.text, mode);
        this.setState({ output: result });
    }

    render(props, state) {
        return h('div', null,
            h('h1', null, 'Input assembly'),
            h(InputAssembly, {
                'mode': this.state.mode,
                'initialtext': this.state.text,
                'onchange': this.handleChange.bind(this)
            }),
            h('h1', null, 'Output code'),
            h(OutputAssembled, {
                'outmode': this.state.outmode,
                'text': this.state.output,
                'onchange': this.handleOutputChange.bind(this)
            }),
        );
    }
}
