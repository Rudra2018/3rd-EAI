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
exports.Button = Button;
var jsx_runtime_1 = require("react/jsx-runtime");
function Button(_a) {
    var _b = _a.className, className = _b === void 0 ? "" : _b, _c = _a.variant, variant = _c === void 0 ? "default" : _c, props = __rest(_a, ["className", "variant"]);
    var base = "inline-flex items-center gap-2 rounded-2xl px-4 py-2 text-sm transition";
    var variants = {
        default: "bg-black text-white hover:opacity-90",
        ghost: "bg-transparent hover:bg-gray-100",
        outline: "border border-gray-300 hover:bg-gray-50",
    };
    return (0, jsx_runtime_1.jsx)("button", __assign({ className: "".concat(base, " ").concat(variants[variant], " ").concat(className) }, props));
}
