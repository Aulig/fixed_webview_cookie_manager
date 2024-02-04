import 'dart:io';

/// This is basically a copy of _Cookie from dart:io, but with some checks in _validateValue removed.
class LaxCookie implements Cookie {
  String _name;
  String _value;
  DateTime? expires;
  int? maxAge;
  String? domain;
  String? _path;
  bool httpOnly = false;
  bool secure = false;
  SameSite? sameSite;

  LaxCookie(String name, String value)
      : _name = _validateName(name),
        _value = _validateValue(value),
        httpOnly = true;

  String get name => _name;
  String get value => _value;

  String? get path => _path;

  set path(String? newPath) {
    _validatePath(newPath);
    _path = newPath;
  }

  set name(String newName) {
    _validateName(newName);
    _name = newName;
  }

  set value(String newValue) {
    _validateValue(newValue);
    _value = newValue;
  }

  LaxCookie.fromSetCookieValue(String value)
      : _name = "",
        _value = "" {
    // Parse the 'set-cookie' header value.
    _parseSetCookieValue(value);
  }

  // Parse a 'set-cookie' header value according to the rules in RFC 6265.
  void _parseSetCookieValue(String s) {
    int index = 0;

    bool done() => index == s.length;

    String parseName() {
      int start = index;
      while (!done()) {
        if (s[index] == "=") break;
        index++;
      }
      return s.substring(start, index).trim();
    }

    String parseValue() {
      int start = index;
      while (!done()) {
        if (s[index] == ";") break;
        index++;
      }
      return s.substring(start, index).trim();
    }

    DateTime _parseCookieDate(String date) {
      const List monthsLowerCase = [
        "jan",
        "feb",
        "mar",
        "apr",
        "may",
        "jun",
        "jul",
        "aug",
        "sep",
        "oct",
        "nov",
        "dec"
      ];

      int position = 0;

      Never error() {
        throw HttpException("Invalid cookie date $date");
      }

      bool isEnd() => position == date.length;

      bool isDelimiter(String s) {
        int char = s.codeUnitAt(0);
        if (char == 0x09) return true;
        if (char >= 0x20 && char <= 0x2F) return true;
        if (char >= 0x3B && char <= 0x40) return true;
        if (char >= 0x5B && char <= 0x60) return true;
        if (char >= 0x7B && char <= 0x7E) return true;
        return false;
      }

      bool isNonDelimiter(String s) {
        int char = s.codeUnitAt(0);
        if (char >= 0x00 && char <= 0x08) return true;
        if (char >= 0x0A && char <= 0x1F) return true;
        if (char >= 0x30 && char <= 0x39) return true; // Digit
        if (char == 0x3A) return true; // ':'
        if (char >= 0x41 && char <= 0x5A) return true; // Alpha
        if (char >= 0x61 && char <= 0x7A) return true; // Alpha
        if (char >= 0x7F && char <= 0xFF) return true; // Alpha
        return false;
      }

      bool isDigit(String s) {
        int char = s.codeUnitAt(0);
        if (char > 0x2F && char < 0x3A) return true;
        return false;
      }

      int getMonth(String month) {
        if (month.length < 3) return -1;
        return monthsLowerCase.indexOf(month.substring(0, 3));
      }

      int toInt(String s) {
        int index = 0;
        for (; index < s.length && isDigit(s[index]); index++);
        return int.parse(s.substring(0, index));
      }

      var tokens = <String>[];
      while (!isEnd()) {
        while (!isEnd() && isDelimiter(date[position])) position++;
        int start = position;
        while (!isEnd() && isNonDelimiter(date[position])) position++;
        tokens.add(date.substring(start, position).toLowerCase());
        while (!isEnd() && isDelimiter(date[position])) position++;
      }

      String? timeStr;
      String? dayOfMonthStr;
      String? monthStr;
      String? yearStr;

      for (var token in tokens) {
        if (token.isEmpty) continue;
        if (timeStr == null &&
            token.length >= 5 &&
            isDigit(token[0]) &&
            (token[1] == ":" || (isDigit(token[1]) && token[2] == ":"))) {
          timeStr = token;
        } else if (dayOfMonthStr == null && isDigit(token[0])) {
          dayOfMonthStr = token;
        } else if (monthStr == null && getMonth(token) >= 0) {
          monthStr = token;
        } else if (yearStr == null &&
            token.length >= 2 &&
            isDigit(token[0]) &&
            isDigit(token[1])) {
          yearStr = token;
        }
      }

      if (timeStr == null ||
          dayOfMonthStr == null ||
          monthStr == null ||
          yearStr == null) {
        error();
      }

      int year = toInt(yearStr);
      if (year >= 70 && year <= 99)
        year += 1900;
      else if (year >= 0 && year <= 69) year += 2000;
      if (year < 1601) error();

      int dayOfMonth = toInt(dayOfMonthStr);
      if (dayOfMonth < 1 || dayOfMonth > 31) error();

      int month = getMonth(monthStr) + 1;

      var timeList = timeStr.split(":");
      if (timeList.length != 3) error();
      int hour = toInt(timeList[0]);
      int minute = toInt(timeList[1]);
      int second = toInt(timeList[2]);
      if (hour > 23) error();
      if (minute > 59) error();
      if (second > 59) error();

      return DateTime.utc(year, month, dayOfMonth, hour, minute, second, 0);
    }

    void parseAttributes() {
      String parseAttributeName() {
        int start = index;
        while (!done()) {
          if (s[index] == "=" || s[index] == ";") break;
          index++;
        }
        return s.substring(start, index).trim().toLowerCase();
      }

      String parseAttributeValue() {
        int start = index;
        while (!done()) {
          if (s[index] == ";") break;
          index++;
        }
        return s.substring(start, index).trim().toLowerCase();
      }

      while (!done()) {
        String name = parseAttributeName();
        String value = "";
        if (!done() && s[index] == "=") {
          index++; // Skip the = character.
          value = parseAttributeValue();
        }
        if (name == "expires") {
          expires = _parseCookieDate(value);
        } else if (name == "max-age") {
          maxAge = int.parse(value);
        } else if (name == "domain") {
          domain = value;
        } else if (name == "path") {
          path = value;
        } else if (name == "httponly") {
          httpOnly = true;
        } else if (name == "secure") {
          secure = true;
        } else if (name == "samesite") {
          switch (value) {
            case "lax":
              sameSite = SameSite.lax;
              break;
            case "none":
              sameSite = SameSite.none;
              break;
            case "strict":
              sameSite = SameSite.strict;
              break;
            default:
              throw HttpException(
                'SameSite value should be one of Lax, Strict or None.');
          };
        }
        if (!done()) index++; // Skip the ; character
      }
    }

    _name = _validateName(parseName());
    if (done() || _name.isEmpty) {
      throw HttpException("Failed to parse header value [$s]");
    }
    index++; // Skip the = character.
    _value = _validateValue(parseValue());
    if (done()) return;
    index++; // Skip the ; character.
    parseAttributes();
  }

  String toString() {
    StringBuffer sb = StringBuffer();
    sb
      ..write(_name)
      ..write("=")
      ..write(_value);
    var expires = this.expires;
    if (expires != null) {
      sb
        ..write("; Expires=")
        ..write(HttpDate.format(expires));
    }
    if (maxAge != null) {
      sb
        ..write("; Max-Age=")
        ..write(maxAge);
    }
    if (domain != null) {
      sb
        ..write("; Domain=")
        ..write(domain);
    }
    if (path != null) {
      sb
        ..write("; Path=")
        ..write(path);
    }
    if (secure) sb.write("; Secure");
    if (httpOnly) sb.write("; HttpOnly");
    if (sameSite != null) sb.write("; $sameSite");

    return sb.toString();
  }

  static String _validateName(String newName) {
    const separators = [
      "(",
      ")",
      "<",
      ">",
      "@",
      ",",
      ";",
      ":",
      "\\",
      '"',
      "/",
      "[",
      "]",
      "?",
      "=",
      "{",
      "}"
    ];
    if (newName == null) throw ArgumentError.notNull("name");
    for (int i = 0; i < newName.length; i++) {
      int codeUnit = newName.codeUnitAt(i);
      if (codeUnit <= 32 ||
          codeUnit >= 127 ||
          separators.contains(newName[i])) {
        throw FormatException(
            "Invalid character in cookie name, code unit: '$codeUnit'",
            newName,
            i);
      }
    }
    return newName;
  }

  static String _validateValue(String newValue) {
    if (newValue == null) throw ArgumentError.notNull("value");
    // Per RFC 6265, consider surrounding "" as part of the value, but otherwise
    // double quotes are not allowed.
    int start = 0;
    int end = newValue.length;
    if (2 <= newValue.length &&
        newValue.codeUnits[start] == 0x22 &&
        newValue.codeUnits[end - 1] == 0x22) {
      start++;
      end--;
    }

    // this is too strict, since it disallows quotation marks
    // for (int i = start; i < end; i++) {
    //   int codeUnit = newValue.codeUnits[i];
    //   if (!(codeUnit == 0x21 ||
    //       (codeUnit >= 0x23 && codeUnit <= 0x2B) ||
    //       (codeUnit >= 0x2D && codeUnit <= 0x3A) ||
    //       (codeUnit >= 0x3C && codeUnit <= 0x5B) ||
    //       (codeUnit >= 0x5D && codeUnit <= 0x7E))) {
    //     throw FormatException(
    //         "Invalid character in cookie value, code unit: '$codeUnit'",
    //         newValue,
    //         i);
    //   }
    // }
    return newValue;
  }

  static void _validatePath(String? path) {
    if (path == null) return;
    for (int i = 0; i < path.length; i++) {
      int codeUnit = path.codeUnitAt(i);
      // According to RFC 6265, semicolon and controls should not occur in the
      // path.
      // path-value = <any CHAR except CTLs or ";">
      // CTLs = %x00-1F / %x7F
      if (codeUnit < 0x20 || codeUnit >= 0x7f || codeUnit == 0x3b /*;*/) {
        throw FormatException(
            "Invalid character in cookie path, code unit: '$codeUnit'");
      }
    }
  }
}


