/**
 * Sends the name of the fragment to the specified function.
 * @param {string} tag - The tag to identify the stack trace.
 * @param {Object} that - The fragment object. Don't use this parameter.
 */
var sendWrap = function (tag, that) {
    send({ "tag": tag, "value": that.toString() });
}

/**
 * Sends the stack trace and calls the specified function.
 * @param {string} tag - The tag to identify the stack trace. If it is empty, it will not print the stack trace.
 * @param {Object} that - The object.
 * @param {Function} func - The function to call.
 */
var getStackTrace = function (tag, that, func) {
    var exception = Java.use("java.lang.Exception").$new();
    var stack = exception.getStackTrace().toString();
    if (tag != "") {
        send({ "tag": tag + "_stack", "stack": stack.toString() });
    }
    if (func != null) {
        func(that);
    }
}

/**
 * Hooks the initialization of the specified class and calls the specified function.
 * @param {string} tag - The tag to identify the stack trace. If it is empty, it will not print the stack trace.
 * @param {string} className - The name of the class to hook.
 * @param {Function} func - The function to call.
 */
function autoHookInit(tag, className, func) {
    var initFunc = function () {
        getStackTrace(tag, this, func);
        this.$init.apply(this, arguments);
    };
    var clazz = Java.use(className);
    for (var i in clazz.$init.overloads) {
        clazz.$init.overloads[i].implementation = initFunc;
    }
}

/**
 * Hooks the initialization of the specified class and calls the specified function.
 * @param {string} tag - The tag to identify the stack trace. If it is empty, it will not print the stack trace.
 * @param {string} className - The name of the class to hook.
 * @param {Function} func - The function to call.
 */
function autoHookOnStart(tag, className, func) {
    var initFunc = function () {
        getStackTrace(tag, this, func);
        this.onStart();
    };
    var clazz = Java.use(className);
    clazz.onStart.implementation = initFunc;
}

/**
 * Hooks the initialization of ImageView, WebView, and ViewFlipper classes.
 */
function hookViewInit() {
    // hook ImageView WebView and ViewFlipper
    console.log("[*] Tracing View init()");
    autoHookInit("ImageView", "android.widget.ImageView")
    autoHookInit("WebView", "android.webkit.WebView")
    autoHookInit("ViewFlipper", "android.widget.ViewFlipper")
}

/**
 * Hooks the loadUrl method of WebView and prints the URL.
 */
function hookWebViewURL() {
    console.log("[*] Tracing WebView loadUrl()");
    var wv = Java.use("android.webkit.WebView");
    let url = "";
    wv.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("loadURL: " + url);
        this.loadUrl(url);
    }
    // get source code
    var wvc = Java.use("android.webkit.WebViewClient");
    wvc.shouldInterceptRequest.overload("android.webkit.WebView", "android.webkit.WebResourceRequest").implementation = function (p1, p2) {
        var url = p2.getUrl().toString();
        console.log("WebViewClient's URL is: " + url + "\n");
        var result = this.shouldInterceptRequest(p1, p2);
        return result;
    }
}

function getId() {
    let date = Date.now();
    let rund = Math.ceil(Math.random() * 1000)
    let id = date + '' + rund;
    return id;
}

function hookWebViewClientContent() {
    var Base64 = Java.use('java.util.Base64');
    var String = Java.use('java.lang.String');
    Java.perform(function () {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onPageFinished.overload('android.webkit.WebView', 'java.lang.String').implementation = function (webView, url) {
            console.log('Page finished loading: ' + url);
            var exception = Java.use("java.lang.Exception").$new();
            var stack = exception.getStackTrace().toString();
            // var id = getId();
            // send({ "tag": "webview_content_stack", "stack": stack, "url": url, "id": id });
            var scriptToExecute = "document.documentElement.outerHTML;";
            var ValueCallback = Java.use('android.webkit.ValueCallback');
            var valueCallbackInstance = Java.registerClass({
                name: 'com.example.ValueCallback',
                implements: [ValueCallback],
                methods: {
                    onReceiveValue: function (value) {
                        var bytes = String.$new(value).getBytes("UTF-8");
                        var encodedBytes = Base64.getEncoder().encode(bytes);
                        var htmlContent = String.$new(encodedBytes).toString();
                        send({ "tag": "webview_content", "url": url, "value": htmlContent, "stack": stack, })
                    }
                }
            });
            webView.evaluateJavascript(scriptToExecute, valueCallbackInstance.$new());
            this.onPageFinished(webView, url);
        };
    });
}

function hookViewChange() {
    console.log("[*] Tracing activity onstart()");
    var Activity = Java.use("android.app.Activity");
    let currentActivity = null;
    Activity.onStart.implementation = function () {
        currentActivity = this;
        sendWrap("activity", currentActivity);
        getStackTrace("activity_stack", this, null);
        this.onStart();
    }
    // autoHookOnStart("", "android.app.Fragment", sendWrap.bind("fragment", null));
    autoHookOnStart("fragment", "android.app.Fragment");
}

function hookRequest() {
    // hook URL backtrace
    console.log("[*] Tracing URL init()");
    var URL = Java.use("java.net.URL");
    // print function calling stack
    URL.$init.overload("java.lang.String").implementation = function (p1) {
        var exception = Java.use("java.lang.Exception").$new();
        var stack = exception.getStackTrace().toString();
        send({ "tag": "url", "value": p1, "stack": stack });
        // console.log(stack);
        this.$init(p1);
    }
}

/**
 * The main function that initializes the hooks.
 */
function main_hook_activity() {
    hookViewInit()
    hookViewChange()
    setTimeout(function () {
        return new Promise((resolve, reject) => {
            Java.perform(function () {
                autoHookOnStart("xfragment", "androidx.fragment.app.Fragment");
                // autoHookOnStart("", "androidx.fragment.app.Fragment", sendWrap.bind("xfragment", null));
                // autohookInit("", "androidx.fragment.app.Fragment", sendName.bind("xfragment-init", null));
            });
        });
    }, 500);
}

function main_hook_web_content() {
    hookWebViewURL()
    hookWebViewClientContent()
}

main_hook_web_content();
main_hook_activity() 