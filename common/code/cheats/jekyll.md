# Supported fenced block languages for highlighting

```bash
rougify list
```

# Initialize array

```
{% assign fruits = "orange,apple,peach" | split: ',' %}
```

# Including dynamic or indirectly related content

```html
<button onclick="someFunction()">Click me</button>

<p id="intro"></p>

<script>

function someFunction() {
    document.getElementById("intro").innerHTML = "{{ page.someContent }}";
}
</script>
```

||

{::options parse_block_html="true" /}
<div class="indirectly-related-content">
# Markdown
</div>
{::options parse_block_html="false" /}

# Styling line numbers

xref. github css - .blob-num
    e.g. https://github.com/moisseev/sqlite3-rdiff/blob/master/sqlite3-rdiff

# Conditional highlight with line numbers

Option 1:

https://github.com/gettalong/kramdown/blob/2e9ee6cd3068e4c9e39bbc9b23350d141a2ed972/doc/options.page
https://github.com/gettalong/kramdown/issues/383
https://kramdown.gettalong.org/rdoc/Kramdown/Options.html

{::options syntax_highlighter_opts="{block: {line_numbers: true\} \}" /}
```diff
- a
+ b
```
{::options syntax_highlighter_opts="{block: {line_numbers: false\} \}" /}

[!] Does not work - `false` applied to whole document

Option 2:

{% highlight diff linenos %}
```diff
- a
+ b
```
{% endhighlight %}

[!] Includes fenced block in content

Option 3:

snippets.html:

```
{% capture foo %}
{% highlight diff linenos %}
- a
+ b
{% endhighlight %}
{% endcapture %}
```

post.md:

<!-- {% raw %} -->
```
{% include snippets.html content=foo %}
```
<!-- {% endraw %} -->
