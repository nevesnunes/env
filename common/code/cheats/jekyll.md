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
