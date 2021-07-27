$(document).ready(function () {
    var panels = $('.accessor-panel');
    for (var i = 0; i < panels.length; i++) {
        var label = $(panels[i]).find('.accessor-body').find('.accessor-text');
        var uri = $(label).attr('data-uri');
        label.click(function () { window.location = uri });
    }
});
