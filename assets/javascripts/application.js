var Base64 = new function() {
  this.encode = function(string) {
    return window.btoa(string);
  };

  this.urlSafeEncode = function(string) {
    return this.encode(string).replace('+', '-').replace('/', '_');
  };

  this.decode = function(base64) {
    try {
      return window.atob(base64.replace('-', '+').replace('_', '/'));
    } catch(err) {
      return '';
    }
  };
}

var AsciiHex = new function() {
  this.encode = function(string) {
    var hexString = '';
    string.split('').forEach(function(b) {
      hexString += b.charCodeAt(0).toString(16);
    });
    return hexString;
  };

  this.decode = function(string) {
    if (string.match(/^[a-f0-9]+$/) !== null) {
      var decodedString = ''
        string.match(/.{1,2}/g).forEach(function(b) {
          decodedString += String.fromCharCode(parseInt(b, 16));
      });
      return decodedString;
    } else {
      return '';
    }
  }
}

var UrlEncode = new function() {
  this.encode = function(string) {
    return window.escape(string);
  };

  this.encodeAll = function(string) {
    encodedString = '';
    string.split('').forEach(function(b) {
      b = b.charCodeAt(0).toString(16).toUpperCase();
      if (b.length === 1) {
        b = '0' + b;
      }
      encodedString += '%' + b;
    });
    return encodedString;
  };

  this.decode = function(string) {
    return window.unescape(string);
  }
}

var HtmlEntity = new function() {
  this.escape = function(string) {
    var escapedString = '';
    string.split('').forEach(function(b) {
      escapedString += '&#x' + b.charCodeAt(0).toString(16) + ';';
    });
    return escapedString;
  };

  this.unescape = function(string) {
    return $('<div />').html(string).text();
  };
}

var BitFlip = new function() {
  this.rint = function (max) {
    return Math.floor(Math.random() * max);
  };

  this.flip = function(input) {
    var where = this.rint(input.length);
    return input.substring(0, where) + String.fromCharCode((input.charCodeAt(where)) ^ (Math.pow(2, this.rint(8)))) + input.substring(where + 1,input.length + 1);
  }
}

var HMAC = new function() {
  this.hash = function(input, secret, messageDigest) {
    if (input === '' || secret === '' || messageDigest === '') {
      return '';
    }

    switch (messageDigest) {
    case 'sha1':
      var hash = CryptoJS.HmacSHA1(input, secret);
      break;
    case 'sha256':
      var hash = CryptoJS.HmacSHA256(input, secret);
      break;
    case 'sha512':
      var hash = CryptoJS.HmacSHA512(input, secret);
      break;
    default:
      var hash = CryptoJS.HmacMD5(input, secret);
      break;
    }

    return hash.toString();
  };
}

var Beautify = new function() {
  this.json = function(code, callback) {
    try {
      json             = JSON.parse(code);
      formattedJson    = JSON.stringify(json, null, 2);
      Rainbow.color(formattedJson, 'javascript', function(highlightedJson) {
        callback(highlightedJson);
      });
    } catch (err) {
      callback(null);
    }
  };

  this.javascript = function(code, callback) {
    try {
      var deobfuscatedJavascript = this.deobfuscateJavascript(code);
      var formattedJavascript    = js_beautify(deobfuscatedJavascript, {
        'indent_size': 2,
        'indent_char': ' '
      });
      Rainbow.color(formattedJavascript, 'javascript', function(highlightedJavascript) {
        callback(highlightedJavascript);
      });
    } catch (err) {
      callback(null);
    }
  };

  this.html = function(code, callback) {
    try {
      var formattedHtml = html_beautify(code, {
        'indent_size': 2,
        'indent_char': ' '
      });
      Rainbow.color(formattedHtml, 'html', function(highlightedHtml) {
        callback(highlightedHtml);
      });
    } catch (err) {
      callback(null);
    }
  };

  this.css = function(code, callback) {
    try {
      var formattedCss = css_beautify(code, {
        'indent_size': 2,
        'indent_char': ' '
      });
      Rainbow.color(formattedCss, 'css', function(highlightedCss) {
        callback(highlightedCss);
      });
    } catch (err) {
      callback(null);
    }
  };

  this.deobfuscateJavascript = function(code) {
    if (JavascriptObfuscator.detect(code)) {
      console.log('Obfuscation detected');
      return JavascriptObfuscator.unpack(code);
    } else if (MyObfuscate.detect(code)) {
      return MyObfuscate.unpack(code);
    } else if (P_A_C_K_E_R.detect(code)) {
      return P_A_C_K_E_R.unpack(code);
    } else if (Urlencoded.detect(code)) {
      return Urlencoded.unpack(code);
    }

    return code;
  };
}

var TabController = new function() {
  this.render = function(tab, input) {
    switch (tab) {
    case 'encoding':
      this.renderEncodingTab(input);
      break;
    case 'decoding':
      this.renderDecodingTab(input);
      break;
    case 'hashing':
      this.renderHashingTab(input);
      break;
    case 'beautifying':
      this.renderBeautifyingTab(input);
      break;
    case 'misc':
      this.renderMiscTab(input);
      break;
    }
  };

  this.renderEncodingTab = function(input) {
    if ($('#url_safe_base64').is(':checked')) {
      $('#base64_encoding').val(Base64.urlSafeEncode(input));
    } else {
      $('#base64_encoding').val(Base64.encode(input));
    }

    if ($('#url_encode_all').is(':checked')) {
      $('#url_encoding').val(UrlEncode.encodeAll(input));
    } else {
      $('#url_encoding').val(UrlEncode.encode(input));
    }

    $('#ascii_hex_encoding').val(AsciiHex.encode(input));
    $('#html_entity_escaping').val(HtmlEntity.escape(input));
  };

  this.renderDecodingTab = function(input) {
    $('#base64_decoding').val(Base64.decode(input));
    $('#url_decoding').val(UrlEncode.decode(input));
    $('#ascii_hex_decoding').val(AsciiHex.decode(input));
    $('#html_entity_unescaping').val(HtmlEntity.unescape(input));
  };

  this.renderHashingTab = function(input) {
    if (input !== '') {
      $('#md5_hashing').val(CryptoJS.MD5(input).toString());
      $('#sha1_hashing').val(CryptoJS.SHA1(input).toString());
      $('#sha256_hashing').val(CryptoJS.SHA256(input).toString());
      $('#hmac_hashing').val(HMAC.hash(input, $('#hmac_hashing_secret').val(), $('#hmac_hashing_message_digest').val()));
    }
  }

  this.renderBeautifyingTab = function(input) {

  };

  this.renderMiscTab = function(input) {
    $('#uppercasing').val(input.toUpperCase());
    $('#lowercasing').val(input.toLowerCase());
    $('#reversed').val(input.split('').reverse().join(''));
    $('#bit_flipping').val(BitFlip.flip(input));
  };
}

$(document).ready(function() {
  $('.use-as-input').tooltip({
    'placement': 'left',
    'title': 'Transfer to input field'
  });

  $('.view-larger').tooltip({
    'placement': 'left',
    'title': 'View output in bigger window'
  });

  $("#input").on('focus', function() {
    $(this).select();
  });

  $('#input').on('textchange', function() {
    var input = $(this).val();
    var currentTab = $('.nav.nav-tabs li.active').attr('data-tab');

    TabController.render(currentTab, input);
  });

  $('.nav.nav-tabs li a').on('click', function() {
    var input = $('#input').val();
    var currentTab = $(this).closest('li').attr('data-tab');

    TabController.render(currentTab, input);
  });

  $('#url_safe_base64').on('click', function() {
    if ($(this).is(':checked')) {
      $('#base64_encoding').val(Base64.urlSafeEncode($('#input').val()));
    } else {
      $('#base64_encoding').val(Base64.encode($('#input').val()));
    }
  });

  $('#url_encode_all').on('click', function() {
    if ($(this).is(':checked')) {
      $('#url_encoding').val(UrlEncode.encodeAll($('#input').val()));
    } else {
      $('#url_encoding').val(UrlEncode.encode($('#input').val()));
    }
  });

  $('.use-as-input').on('click', function(e) {
    e.preventDefault();
    var value = $($(this).attr('data-target')).val();
    if (value !== '') {
      $('#input').val(value);
      var currentTab = $('.nav.nav-tabs li.active').attr('data-tab');
      TabController.render(currentTab, value);
    }
  });

  $('.view-larger').on('click', function(e) {
    e.preventDefault();
    var target = $($(this).attr('data-target'));
    if ($(target).is('pre')) {
      var modalBody = $('<pre />').addClass('output-field large').html($(target).html());
    } else {
      var modalBody = $('<textarea readonly />').addClass('output-field large').val($(target).val());
    }
    $('#view-larger-modal .modal-body').html(modalBody);
    $('#view-larger-modal').modal('show');
  });

  $('#hmac_hashing_secret').on('textchange', function() {
    $('#hmac_hashing').val(HMAC.hash($('#input').val(), $('#hmac_hashing_secret').val(), $('#hmac_hashing_message_digest').val()));
  });

  $('#hmac_hashing_message_digest').on('change', function() {
    $('#hmac_hashing').val(HMAC.hash($('#input').val(), $('#hmac_hashing_secret').val(), $('#hmac_hashing_message_digest').val()));
  });

  $('#beautify_javascript').on('click', function(e) {
    e.preventDefault();
    code = $('#input').val();

    if (code !== '') {
      $('#javascript_beautifying_container .loader').css('display', 'inline-block');
      setTimeout(function() {
        Beautify.javascript(code, function(beautified) {
          $('#javascript_beautifying_container .loader').css('display', 'none');
          if (beautified !== null) {
            $('#javascript_beautifying').html(beautified);
          } else {
            $('#javascript_beautifying').html('<p>Invalid Javascript.</p>');
          }
        });
      }, 100);
    }
  });

  $('#beautify_json').on('click', function(e) {
    e.preventDefault();
    code = $('#input').val();

    if (code !== '') {
      $('#json_beautifying_container .loader').css('display', 'inline-block');
      setTimeout(function() {
        Beautify.json(code, function(beautified) {
          $('#json_beautifying_container .loader').css('display', 'none');
          if (beautified !== null) {
            $('#json_beautifying').html(beautified);
          } else {
            $('#json_beautifying').html('<p>Invalid JSON.</p>');
          }
        });
      }, 100);
    }
  });

  $('#beautify_html').on('click', function(e) {
    e.preventDefault();
    code = $('#input').val();

    if (code !== '') {
      $('#html_beautifying_container .loader').css('display', 'inline-block');
      setTimeout(function() {
        Beautify.html(code, function(beautified) {
          $('#html_beautifying_container .loader').css('display', 'none');
          if (beautified !== null) {
            $('#html_beautifying').html(beautified);
          } else {
            $('#html_beautifying').html('<p>Invalid HTML.</p>');
          }
        });
      }, 100);
    }
  });

  $('#beautify_css').on('click', function(e) {
    e.preventDefault();
    code = $('#input').val();

    if (code !== '') {
      $('#css_beautifying_container .loader').css('display', 'inline-block');
      setTimeout(function() {
        Beautify.css(code, function(beautified) {
          $('#css_beautifying_container .loader').css('display', 'none');
          if (beautified !== null) {
            $('#css_beautifying').html(beautified);
          } else {
            $('#css_beautifying').html('<p>Invalid CSS.</p>');
          }
        });
      }, 100);
    }
  });

  $('#flip_again').on('click', function(e) {
    e.preventDefault();
    $('#bit_flipping').val(BitFlip.flip($('#input').val()));
  });

  $('#input').focus();
});
