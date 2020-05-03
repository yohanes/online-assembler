function toHex(c) {
    var res = c.toString(16);
    if (res.length == 1) res = "0" + res;
    return res;
  }

  function get_hex_from_text(intext) {
    var text = intext.trim()

    //try hex: does it only contain "0-9A-Fa-f\r\n\t "
    let re = /^[0-9A-Fa-f\t\r\n ]+$/
    if (re.test(text)) {

      text = text.replace(/[\r|\n|\t| ]/g, "")
      if ((text.length % 2) == 1) {
        return { ok: false, type: "pure hex", text: "Invalid HEX input: odd length" };
      }
      return { ok: true, type: "pure hex", text: text };
    }

    //try string in the form of \x12\x34
    //with and without prefix quote
    var tmp = text.replace(/[\r|\n|\t| ]/g, "")

    //with quote
    let rex1 = /^"(\\x([0-9A-Fa-f][0-9A-Fa-f]))+"$/
    if (rex1.test(tmp)) {
      text = tmp.replace(/\\x/g, "").replace(/"/g, "");
      return { ok: true, type: "hex string", text: text };
    }

    //with single quote
    let rex2 = /^'(\\x([0-9A-Fa-f][0-9A-Fa-f]))+'$/
    if (rex2.test(tmp)) {
      text = tmp.replace(/\\x/g, "").replace(/'/g, "");
      return { ok: true, type: "hex string", text: text };
    }      

    //without quotes
    let rex = /^(\\x([0-9A-Fa-f][0-9A-Fa-f]))+$/
    if (rex.test(tmp)) {
      text = tmp.replace(/\\x/g, "");
      return { ok: true, type: "hex escape", text: text };
    }

    //test if this is array: 0x0a, 0x0b, may be inside {} (C syntax) or [] (Python syntax)
    if (tmp.startsWith("[") && tmp.endsWith("]")) {
      tmp = tmp.substring(1, tmp.length-1)
    }
    if (tmp.startsWith("{") && tmp.endsWith("}")) {
      tmp = tmp.substring(1, tmp.length-1)
    }

    if (tmp.indexOf(",")>0) {
      var parts = tmp.split(",")
      var res = '';
      var valid = true;
      for (const part of parts) {
          var ix = parseInt(part)
          if (isNaN(ix)) {
            valid = false;
            break;
          }
          res += toHex(ix);
      }
      if (valid) {
        return { ok: true, type: "array", text: res };
      }
    }

    let base64regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    if (base64regex.test(tmp)) {
      var raw = atob(tmp);
      var decoded = '';
      for (let i = 0; i < raw.length; i++) {
          const hex = raw.charCodeAt(i).toString(16);
          decoded += (hex.length === 2 ? hex : '0' + hex);
      }        
      return { ok: true, type: "base64", text: decoded };
    }

    return { ok: true, type: "unknown", text: text };
  }

  const disassember_selections = {
    'x86_16': 'x86 16bit',
    'x86_32': 'x86 32bit',
    'x86_64': 'x86 64bit',
    "arm": "ARM - little endian",
    "thumb": "THUMB - little endian",
    "thumbbe": "THUMB - big endian",
    "arm64": "ARM64",
    "hexagon": "Hexagon",
    "mips32": "Mips - little endian",
    "mips32be": "Mips - big endian",
    "mips64": "Mips64 - little endian",
    "mips64be": "Mips64 - bigendian endian",
    "sparc": "Sparc - little endian",
    "sparcbe": "Sparc - big endian",
    "sparc64be": "Sparc64 - big endian",
    "systemz": "System Z (S390x)",
    "xcore": "XCore"
  }

  class SelectDisassemblerInputType extends Component {

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
      for (const [key, value] of Object.entries(disassember_selections)) {
        var prop = { 'value': key };
        if (key == this.state.mode) {
          prop['selected'] = true;
        }
        options.push(h('option', prop, value))
      }
      var sel = h('select', { 'onchange': this.handleChange.bind(this) }, options);
      return h('div', null,
        h('label', null, "Arch: "), sel);;
    }
  }

  class InputCode extends Component {
    constructor(props) {
      super(props);
      const {ok, type, text} = get_hex_from_text(props.initialtext)
      this.state = {
        mode: props.mode,
        text: props.initialtext,
        inputtype: type,
        hextext: text
      }
    }

    handleArchChange(mode) {
      this.state.mode = mode;
      this.props.onchange(this.state.mode, this.state.text)
    }

    handleTextChange(e) {
      this.state.text = e.target.value;
      const {ok, type, text} = get_hex_from_text(e.target.value);
      this.state.hextext = text;
      this.state.inputtype = type;
      this.props.onchange(this.state.mode, e.target.value)
    }

    render(props, state) {
      return h('div', null,
        h(SelectDisassemblerInputType, {
          'mode': this.state.mode,
          'onchange': this.handleArchChange.bind(this)
        }),
        h('textarea', {
          'rows': 10,
          'cols': 60,
          "autocomplete": "off",
          "autocorrect": "off",
          "autocapitalize": "off",
          "spellcheck": false,
          'oninput': this.handleTextChange.bind(this)
        },
          state.text),
          h('span',null, "Hex input (from "+this.state.inputtype+"): "),
          h('pre',null,this.state.hextext)
      );
    }
  }


  class OutputAssembly extends Component {
    constructor(props) {
      super(props);
    }

    render(props, state) {
      return h('div', null,
        h('textarea', {
          'rows': 10, 'cols': 60,
          "autocomplete": "off",
          "autocorrect": "off",
          "autocapitalize": "off",
          "spellcheck": false
        }, this.props.text));
    }
  }

  class DisassemblerApp extends Component {

    constructor() {
      super();
      this.state = {
        mode: Object.entries(disassember_selections)[0][0],
        text: "90",
      }
      this.state.output = this.computeOutput(this.state.mode, this.state.text);

    }

    computeOutput(mode, inputtext) {
      //clean the text

      const { ok, type, text } = get_hex_from_text(inputtext);
      if (!ok) {
        return text;
      }

      var restext = disassemble_c(mode, text, 0x0);
      console.log(restext);
      var res = JSON.parse(restext);
      if (res.error) {
        return res.message;
      }
      var lines = "";
      for (const inst of res.instructions) {
        lines += inst.address + ":\t" + inst.mnemonic + "  " + inst.opstr + "\n";
      }
      return lines;

    }

    handleChange(mode, intext) {
      if (intext == null)
        return;        
      this.setState({ mode: mode, text: intext });
      var result = this.computeOutput(mode, intext);
      this.setState({ output: result });
    }


    render(props, state) {
      return h('div', null,
        h('h1', null, 'Input code'),
        h(InputCode, {
          'mode': this.state.mode,
          'initialtext': this.state.text,
          'onchange': this.handleChange.bind(this)
        }),
        h('h1', null, 'Disassembly'),
        h(OutputAssembly, {
          'outmode': this.state.outmode,
          'text': this.state.output
        }),
      );
    }
  }