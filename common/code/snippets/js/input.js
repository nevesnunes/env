function getHasChanges() {
    var hasChanges = false;

    $(":input:not(:button):not([type=hidden])").each(function () {
        if ((this.type == "text" || this.type == "textarea" || this.type == "hidden") && this.defaultValue != this.value) {
            hasChanges = true;
            return false;             }
        else {
            if ((this.type == "radio" || this.type == "checkbox") && this.defaultChecked != this.checked) {
                hasChanges = true;
                return false;                 }
            else {
                if ((this.type == "select-one" || this.type == "select-multiple")) {
                    for (var x = 0; x < this.length; x++) {
                        if (this.options[x].selected != this.options[x].defaultSelected) {
                            hasChanges = true;
                            return false;
                        }
                    }
                }
            }
        }
    });

    return hasChanges;
}

function acceptChanges() {
    $(":input:not(:button):not([type=hidden])").each(function () {
        if (this.type == "text" || this.type == "textarea" || this.type == "hidden") {
            this.defaultValue = this.value;
        }
        if (this.type == "radio" || this.type == "checkbox") {
            this.defaultChecked = this.checked;
        }
        if (this.type == "select-one" || this.type == "select-multiple") {
            for (var x = 0; x < this.length; x++) {
                this.options[x].defaultSelected = this.options[x].selected
            }
        }
    });
}
