javascript:(function(){
    function getJavaScript(url, success) {
        var script = document.createElement('script');
            script.src = url;
        var head = document.getElementsByTagName('head')[0],
            done = false;
        script.onload = script.onreadystatechange = function(){
            if (!done && (!this.readyState || this.readyState == 'loaded' || this.readyState == 'complete')) {
                done = true;
                success();
                script.onload = script.onreadystatechange = null;
                head.removeChild(script);
            }
        };
        head.appendChild(script);
    }
    function addCSVLinks() {
        jQuery('.csvLink').remove();
        
        jQuery('table').each(function(index){
            jQuery(this).attr('data-csvtable', index).before('<a href="#" class="csvLink" data-forcsvtable="' + index + '">Export to CSV</a>');
        });
        
        jQuery('.csvLink').click(function(){
            var text = '';
            var csvTableIndex = jQuery(this).attr('data-forcsvtable');
            jQuery('table[data-csvtable="' + csvTableIndex + '"] tr').each(function(){
                jQuery('td, th', this).each(function(index){
                    if(index != 0) {
                        text += ',';
                    }
                    text += '"' + formatedText(jQuery(this).html()) + '"';
                });
                text += '\r\n';
            });
            jQuery('.csvLink').remove();
            downloadCSVFile('TableExport.csv', 'text/csv', text);
        });
    }
  function formatedText(html) {
    var ret = html;
    
    //replace line breaks
    ret = ret.replace(/\n/g, ' ');
    
    //replace tabs
    ret = ret.replace(/\t/g, ' ');
    
    //replace multiple spaces
    ret = ret.replace(/\s+/g, ' ');
    
    //Fix html encoded characters
    ret = decodeHtml(ret);
    
    //Deal with lines breaks and paragraphs
    ret = ret.replace(/<br>/ig, '\n<br>');
    ret = ret.replace(/<br/ig, '\n<br ');
    ret = ret.replace(/<p/ig, '\n<p ');
    
    //Deal with quotes
    ret = ret.replace(/"/ig, '""');
    
    //Deal first character being line break
    ret = ret.replace(/^\n/, '');
    
    //Remove HTML tags
    ret = ret.replace(/(<([^>]+)>)/ig,"");
    return ret;
  }
  function decodeHtml(html) {
    var txt = document.createElement('textarea');
    txt.innerHTML = html;
    return txt.value;
  }
    function downloadCSVFile(filename, mime, text) {
        if (window.navigator.msSaveOrOpenBlob){
            // IE 10+
            var blob = new Blob([decodeURIComponent(encodeURI(text))], {
                type: 'text/csv;charset=utf-8'
            });
            window.navigator.msSaveBlob(blob, filename);
        } else {
            var pom = document.createElement('a');
            pom.setAttribute('href', 'data:' + mime + ';charset=utf-8,' + encodeURIComponent(text));
            pom.setAttribute('download', filename);
            document.body.appendChild(pom);
            pom.click();
            document.body.removeChild(pom);
        }
    }
    if(typeof jQuery == 'undefined') {
        getJavaScript(
            '//code.jquery.com/jquery-latest.min.js',
            function(){
                addCSVLinks();
            }
        )
    } else {
        addCSVLinks();
    }
})();
