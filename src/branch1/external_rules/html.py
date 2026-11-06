"""Small HTMLParser wrapper for the selectors used by our posture rules."""
from html.parser import HTMLParser


class Node:
    def __init__(self, tag=None, attrs=None):
        self.tag, self.attrs, self.children = tag, dict(attrs or []), []

    def get(self, key, default=None):
        return self.attrs.get(key, default)

    def get_text(self, separator="", strip=False):
        text = [c.get_text(separator, strip) if isinstance(c, Node) else c for c in self.children]
        if strip:
            text = [t.strip() for t in text if t.strip()]
        return separator.join(text)

    def find_all(self, name=None, attrs=None, **kwargs):
        matches = []
        filters = {**(attrs or {}), **kwargs}
        for node in self.children:
            if not isinstance(node, Node):
                continue
            ok = name is None or node.tag == name
            for key, desired in filters.items():
                actual = node.get(key)
                ok = ok and (actual is not None if desired is True else
                             bool(desired.search(actual or "")) if hasattr(desired, "search") else actual == desired)
            if ok:
                matches.append(node)
            matches.extend(node.find_all(name, filters))
        return matches

    def find(self, name=None, attrs=None, **kwargs):
        found = self.find_all(name, attrs, **kwargs)
        return found[0] if found else None


class Document(Node, HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, html, parser="html.parser"):
        Node.__init__(self)
        HTMLParser.__init__(self, convert_charrefs=True)
        self.stack = [self]
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs)
        self.stack[-1].children.append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack)-1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)
