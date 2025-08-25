"use strict";
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SimpleDiff = SimpleDiff;
var jsx_runtime_1 = require("react/jsx-runtime");
var react_1 = require("react");
function toLines(value) {
    if (typeof value === "string") {
        try {
            var parsed = JSON.parse(value);
            return JSON.stringify(parsed, null, 2).split("\n");
        }
        catch (_a) {
            return value.split("\n");
        }
    }
    try {
        return JSON.stringify(value, null, 2).split("\n");
    }
    catch (_b) {
        return String(value).split("\n");
    }
}
function SimpleDiff(_a) {
    var oldValue = _a.oldValue, newValue = _a.newValue, _b = _a.className, className = _b === void 0 ? "" : _b;
    var left = toLines(oldValue);
    var right = toLines(newValue);
    var max = Math.max(left.length, right.length);
    return ((0, jsx_runtime_1.jsx)("div", { className: "grid grid-cols-2 gap-3 text-sm ".concat(className), children: __spreadArray([], Array(max), true).map(function (_, i) {
            var _a, _b;
            var l = (_a = left[i]) !== null && _a !== void 0 ? _a : "";
            var r = (_b = right[i]) !== null && _b !== void 0 ? _b : "";
            var changed = l !== r;
            return ((0, jsx_runtime_1.jsxs)(react_1.default.Fragment, { children: [(0, jsx_runtime_1.jsxs)("pre", { className: "rounded-xl border p-2 font-mono leading-5 ".concat(changed ? "bg-red-50" : "bg-gray-50"), children: [(0, jsx_runtime_1.jsx)("span", { className: "mr-2 text-gray-400", children: String(i + 1).padStart(3, " ") }), l] }), (0, jsx_runtime_1.jsxs)("pre", { className: "rounded-xl border p-2 font-mono leading-5 ".concat(changed ? "bg-green-50" : "bg-gray-50"), children: [(0, jsx_runtime_1.jsx)("span", { className: "mr-2 text-gray-400", children: String(i + 1).padStart(3, " ") }), r] })] }, i));
        }) }));
}
