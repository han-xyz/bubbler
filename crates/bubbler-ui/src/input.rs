//! The one-line text field the prompts are made of.
//!
//! Hand-rolled rather than taken from a crate: what it holds is a KDL
//! node or an instance name, both short, and forty lines that are
//! testable against a `String` cost less than a dependency.

/// A line of text and a cursor in it, counted in characters so that a
/// multi-byte character is one step of the cursor and never a split byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Input {
    value: String,
    cursor: usize,
}

impl Input {
    /// A field holding `value`, with the cursor at its end, which is
    /// where a pre-filled line is edited from.
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.chars().count();
        Self { value, cursor }
    }

    /// What has been typed.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Where the cursor is, in characters from the start.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Byte offset of the cursor, for slicing the value.
    fn offset(&self) -> usize {
        self.value
            .char_indices()
            .nth(self.cursor)
            .map_or(self.value.len(), |(i, _)| i)
    }

    /// Type a character at the cursor.
    pub fn insert(&mut self, c: char) {
        let at = self.offset();
        self.value.insert(at, c);
        self.cursor += 1;
    }

    /// Delete the character before the cursor.
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let at = self.offset();
        self.value.remove(at);
    }

    /// Delete the character under the cursor.
    pub fn delete(&mut self) {
        if self.cursor < self.value.chars().count() {
            let at = self.offset();
            self.value.remove(at);
        }
    }

    /// Delete everything before the cursor, which is `^U`.
    pub fn clear_before(&mut self) {
        let at = self.offset();
        self.value.replace_range(..at, "");
        self.cursor = 0;
    }

    /// Move the cursor one character left.
    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Move the cursor one character right.
    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.value.chars().count());
    }

    /// Move the cursor to the start of the line.
    pub fn home(&mut self) {
        self.cursor = 0;
    }

    /// Move the cursor to the end of the line.
    pub fn end(&mut self) {
        self.cursor = self.value.chars().count();
    }

    /// The part of the value a field `width` characters wide shows, and
    /// where the cursor sits in it: the tail once the cursor has passed
    /// the right edge, so a line longer than its field stays editable.
    pub fn view(&self, width: usize) -> (&str, usize) {
        if width == 0 {
            return ("", 0);
        }
        let first = (self.cursor + 1).saturating_sub(width);
        let start = self
            .value
            .char_indices()
            .nth(first)
            .map_or(self.value.len(), |(i, _)| i);
        (&self.value[start..], self.cursor - first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_and_deleting_happen_where_the_cursor_is() {
        let mut input = Input::new("wayland");
        assert_eq!(input.cursor(), 7);
        input.home();
        input.insert('x');
        assert_eq!(input.value(), "xwayland");
        assert_eq!(input.cursor(), 1);
        input.backspace();
        assert_eq!(input.value(), "wayland");
        input.backspace();
        assert_eq!(input.value(), "wayland", "nothing before the start");
        input.delete();
        assert_eq!(input.value(), "ayland");
        input.end();
        input.delete();
        assert_eq!(input.value(), "ayland", "nothing past the end");
    }

    #[test]
    fn the_cursor_walks_characters_and_not_bytes() {
        let mut input = Input::new("héllo");
        input.home();
        input.right();
        input.insert('x');
        assert_eq!(input.value(), "hxéllo");
        input.left();
        input.delete();
        assert_eq!(input.value(), "héllo");
    }

    #[test]
    fn a_line_longer_than_its_field_scrolls_with_the_cursor() {
        let mut input = Input::new("home-share \"Downloads\" mode=rw");
        assert_eq!(input.view(10), ("\" mode=rw", 9));
        input.home();
        assert_eq!(input.view(10), ("home-share \"Downloads\" mode=rw", 0));
        assert_eq!(input.view(0), ("", 0));
    }

    #[test]
    fn control_u_takes_the_line_up_to_the_cursor() {
        let mut input = Input::new("network \"host\"");
        input.left();
        input.clear_before();
        assert_eq!(input.value(), "\"");
        assert_eq!(input.cursor(), 0);
    }
}
