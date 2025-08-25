"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Alert = Alert;
exports.AlertTitle = AlertTitle;
exports.AlertDescription = AlertDescription;
var jsx_runtime_1 = require("react/jsx-runtime");
function Alert(_a) {
    var _b = _a.className, className = _b === void 0 ? "" : _b, props = __rest(_a, ["className"]);
    return (0, jsx_runtime_1.jsx)("div", __assign({ className: "rounded-2xl border border-amber-300 bg-amber-50 p-4 ".concat(className) }, props));
}
function AlertTitle(_a) {
    var _b = _a.className, className = _b === void 0 ? "" : _b, props = __rest(_a, ["className"]);
    return (0, jsx_runtime_1.jsx)("h4", __assign({ className: "mb-1 text-sm font-semibold ".concat(className) }, props));
}
function AlertDescription(_a) {
    var _b = _a.className, className = _b === void 0 ? "" : _b, props = __rest(_a, ["className"]);
    return (0, jsx_runtime_1.jsx)("p", __assign({ className: "text-sm text-amber-800 ".concat(className) }, props));
}
