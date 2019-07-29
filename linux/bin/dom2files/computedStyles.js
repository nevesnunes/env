var fs = require('fs');

function getFileUrl(str) {
  var pathName = fs.absolute(str).replace(/\\/g, '/');
  // Windows drive letter must be prefixed with a slash
  if (pathName[0] !== "/") {
    pathName = "/" + pathName;
  }
  return encodeURI("file://" + pathName);
}

var system = require('system');
var args = system.args;
var filename = args[1];
var height = args[2];
var width = args[3];
var outputDir = args[4];

var url = getFileUrl(filename);

console.log("url " + url + ", height " + height + ", width " + width + ", outputDir " + outputDir);

page = require('webpage').create();

page.viewportSize = {
  width: width,
  height: height
};

page.onConsoleMessage = function(msg) {
  return console.log(msg);
};

page.open(url, function(status) {
  if (status !== "success") {
    return console.log("Unable to open " + url);
  } else {
    page.evaluate(function() {
      var attributes, el, elements, i, j, k, l, len, output, propertyName, ref1, ref2, rule, ruleList, rules, style;
      output = {
        url: location,
        retrievedAt: new Date(),
        elements: []
      };
      elements = document.getElementsByTagName("*");
      console.log("elements " + elements);
      for (j = 0, len = elements.length; j < len; j++) {
        el = elements[j];
        style = window.getComputedStyle(el);
        attributes = {};
        for (i = k = 0, ref1 = style.length; 0 <= ref1 ? k < ref1 : k > ref1; i = 0 <= ref1 ? ++k : --k) {
          propertyName = style.item(i);
          attributes[propertyName] = style.getPropertyValue(propertyName);
        }
        ruleList = el.ownerDocument.defaultView.getMatchedCSSRules(el, '') || [];
        rules = [];
        for (i = l = 0, ref2 = ruleList.length; 0 <= ref2 ? l < ref2 : l > ref2; i = 0 <= ref2 ? ++l : --l) {
          rule = ruleList[i];
          if (rule.parentStyleSheet !== null) {
              rules.push({
                selectorText: rule.selectorText,
                parentStyleSheet: rule.parentStyleSheet.href
              });
          }
        }
        output.elements.push({
          id: el.id,
          className: el.className,
          nodeName: el.nodeName,
          offsetHeight: el.offsetHeight,
          offsetWidth: el.offsetWidth,
          offsetTop: el.offsetTop,
          offsetLeft: el.offsetLeft,
          computedStyle: attributes,
          styleRules: rules
        });
      }
      output.elements.forEach(function(element) {
          if (element.nodeName.match(/svg/i)) {
              console.log(JSON.stringify(element, null, 4));
              return;
          }
      });
    });
    return window.setTimeout((function() {
      page.render(outputDir + "/output.png");
      return phantom.exit();
    }), 200);
  }
});
