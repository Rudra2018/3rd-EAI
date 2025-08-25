"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Tabs = Tabs;
exports.TabsList = TabsList;
exports.TabsTrigger = TabsTrigger;
exports.TabsContent = TabsContent;
var jsx_runtime_1 = require("react/jsx-runtime");
function Tabs(_a) {
    var value = _a.value, onValueChange = _a.onValueChange, _b = _a.className, className = _b === void 0 ? "" : _b, children = _a.children;
    return (0, jsx_runtime_1.jsx)("div", { className: className, "data-value": value, "data-onchange": !!onValueChange, children: children });
}
function TabsList(_a) {
    var _b = _a.className, className = _b === void 0 ? "" : _b, children = _a.children;
    return (0, jsx_runtime_1.jsx)("div", { className: "mb-3 inline-flex rounded-xl border p-1 ".concat(className), children: children });
}
function TabsTrigger(_a) {
    var value = _a.value, current = _a.current, onSelect = _a.onSelect, children = _a.children;
    var active = value === current;
    return ((0, jsx_runtime_1.jsx)("button", { type: "button", onClick: function () { return onSelect(value); }, className: "rounded-lg px-3 py-1.5 text-sm ".concat(active ? "bg-black text-white" : "text-gray-600 hover:bg-gray-100"), children: children }));
}
function TabsContent(_a) {
    var value = _a.value, current = _a.current, children = _a.children;
    if (value !== current)
        return null;
    return (0, jsx_runtime_1.jsx)("div", { children: children });
}
