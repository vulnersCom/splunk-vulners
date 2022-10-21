
/**
 * This is an example using pure react, with no JSX
 * If you would like to use JSX, you will need to use Babel to transpile your code
 * from JSK to JS. You will also need to use a task runner/module bundler to
 * help build your app before it can be used in the browser.
 * Some task runners/module bundlers are : gulp, grunt, webpack, and Parcel
 */

 import * as Setup from "./setup_page.js";

 define(["react", "splunkjs/splunk"], function(react, splunk_js_sdk){
   const e = react.createElement;
 
   class SetupPage extends react.Component {
     constructor(props) {
       super(props);
 
       this.state = {
         token: ''
       };
 
       this.handleChange = this.handleChange.bind(this);
       this.handleSubmit = this.handleSubmit.bind(this);
     }
 
     handleChange(event) {
       this.setState({ ...this.state, [event.target.name]: event.target.value})
     }
 
     async handleSubmit(event) {
       event.preventDefault();
 
       await Setup.perform(splunk_js_sdk, this.state)
     }
 
     render() {
       return e("div", null, [
         e("h2", null, "Vulners API Token and Endpoint Setup Page"),
         e("div", null, [
           e("form", { onSubmit: this.handleSubmit }, [
             e("label", null,"Vulners Api Token"),
             e("input", { type: "text", name: "vulners_api_token", value: this.state.vulners_api_token, onChange: this.handleChange }),
             e("small", { class: 'setup_small'}, "Use your API Token from https://vulners.com/ platform."),
             e("label", null, "Vulners Endpoint"),
             e("input", { type: "text", name: "vulners_endpoint_value", value: this.state.vulners_endpoint_value, onChange: this.handleChange }),
             e("small", { class: 'setup_small'}, "Set your custom Vulners Proxy endpoint (set empty to use default https://vulners.com endpoint). Example: http://192.168.1.1:8000. Read more about Vulners Proxy on https://github.com/vulnersCom/vulners-proxy."),
             e("input", { type: "submit", value: "Save configuration" })
           ])
         ])
       ]);
     }
   }
 
   return e(SetupPage);
 });
 