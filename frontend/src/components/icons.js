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
exports.Database = exports.Link2 = exports.ListFilter = exports.Diff = exports.ExternalLink = exports.Bug = exports.ShieldCheck = exports.Upload = exports.Loader2 = void 0;
var jsx_runtime_1 = require("react/jsx-runtime");
function Svg(props) {
    var _a = props.className, className = _a === void 0 ? "h-4 w-4" : _a, rest = __rest(props, ["className"]);
    return (0, jsx_runtime_1.jsx)("svg", __assign({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, className: className }, rest));
}
var Loader2 = function (p) { return ((0, jsx_runtime_1.jsxs)(Svg, __assign({}, p, { className: "animate-spin ".concat(p.className || "h-4 w-4"), children: [(0, jsx_runtime_1.jsx)("circle", { cx: "12", cy: "12", r: "9", strokeOpacity: "0.3" }), (0, jsx_runtime_1.jsx)("path", { d: "M21 12a9 9 0 0 0-9-9", strokeLinecap: "round" })] }))); };
exports.Loader2 = Loader2;
var Upload = function (p) { return ((0, jsx_runtime_1.jsxs)(Svg, __assign({}, p, { children: [(0, jsx_runtime_1.jsx)("path", { d: "M12 16V4M7 9l5-5 5 5" }), (0, jsx_runtime_1.jsx)("path", { d: "M20 16v2a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2" })] }))); };
exports.Upload = Upload;
var ShieldCheck = function (p) { return ((0, jsx_runtime_1.jsxs)(Svg, __assign({}, p, { children: [(0, jsx_runtime_1.jsx)("path", { d: "M12 3l8 4v5a8 8 0 1 1-16 0V7l8-4" }), (0, jsx_runtime_1.jsx)("path", { d: "M9 12l2 2 4-4" })] }))); };
exports.ShieldCheck = ShieldCheck;
var Bug = function (p) { return ((0, jsx_runtime_1.jsxs)(Svg, __assign({}, p, { children: [(0, jsx_runtime_1.jsx)("circle", { cx: "12", cy: "12", r: "3" }), (0, jsx_runtime_1.jsx)("path", { d: "M4 12h4m8 0h4M6 6l3 3m9-3l-3 3M6 18l3-3m9 3l-3-3M12 5v2m0 10v2" })] }))); };
exports.Bug = Bug;
var ExternalLink = function (p) { return ((0, jsx_runtime_1.jsxs)(Svg, __assign({}, p, { children: [(0, jsx_runtime_1.jsx)("path", { d: "M14 3h7v7" }), (0, jsx_runtime_1.jsx)("path", { d: "M21 3l-9 9" }), (0, jsx_runtime_1.jsx)("path", { d: "M5 12v7a2 2 0 0 0 2 2h7" })] }))); };
exports.ExternalLink = ExternalLink;
var Diff = function (p) { return ((0, jsx_runtime_1.jsxs)(Svg, __assign({}, p, { children: [(0, jsx_runtime_1.jsx)("path", { d: "M8 3h8v8H8z" }), (0, jsx_runtime_1.jsx)("path", { d: "M3 13h8v8H3z" }), (0, jsx_runtime_1.jsx)("path", { d: "M13 13h8v8h-8z" })] }))); };
exports.Diff = Diff;
var ListFilter = function (p) { return ((0, jsx_runtime_1.jsx)(Svg, __assign({}, p, { children: (0, jsx_runtime_1.jsx)("path", { d: "M3 6h18M6 12h12M10 18h4" }) }))); };
exports.ListFilter = ListFilter;
var Link2 = function (p) { return ((0, jsx_runtime_1.jsxs)(Svg, __assign({}, p, { children: [(0, jsx_runtime_1.jsx)("path", { d: "M10 13a5 5 0 0 1 0-7l1-1a5 5 0 0 1 7 7l-1 1" }), (0, jsx_runtime_1.jsx)("path", { d: "M14 11a5 5 0 0 1 0 7l-1 1a5 5 0 0 1-7-7l1-1" })] }))); };
exports.Link2 = Link2;
var Database = function (p) { return ((0, jsx_runtime_1.jsxs)(Svg, __assign({}, p, { children: [(0, jsx_runtime_1.jsx)("ellipse", { cx: "12", cy: "5", rx: "7", ry: "3" }), (0, jsx_runtime_1.jsx)("path", { d: "M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5" }), (0, jsx_runtime_1.jsx)("path", { d: "M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" })] }))); };
exports.Database = Database;
