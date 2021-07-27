var layoutComposite = null;
function LayoutComposite() {
    this.configure = function () { }

    $('document').ready(function () {
        layoutComposite.configure();
    });
}; layoutComposite = new LayoutComposite();

var toastComposite = null;
function ToastComposite() {
    this.load = function () {
        var element = $('.toast');
        var title = element.find('.toast-title').html();
        var message = element.find('.toast-body').html();
        var level = element.find('.toast-level').html();
        if (message.trim() != '') {
            this.show(title, message, level);
        }
    }

    this.show = function (title, message, level) {
        var element = $('.toast');
        var duration = this.time(level);
        element.find('.toast-title').html(title);
        element.find('.toast-body').html(message);
        element.find('.toast-dialog').addClass('toast-dialog-' + level);
        element.fadeIn(500);
        window.setTimeout(function () { toastComposite.hide() }, duration);
    }

    this.hide = function () {
        var element = $('.toast');
        element.fadeOut(800);

    }

    this.reset = function () {
        var element = $('.toast');
        element.find('.toast-level').html('')
        element.find('.toast-title').html('');
        element.find('.toast-body').html('');
        element.find('.toast-dialog').removeClass('.toast-dialog-success');
        element.find('.toast-dialog').removeClass('.toast-dialog-failure');
        element.find('.toast-dialog').removeClass('.toast-dialog-information');
    }

    this.time = function (level) {
        if (level == toastLevel.success) { return 1500; }
        else { return 2500; }
    }

    $(document).ready(function () {
        toastComposite.load();
    });
}; toastComposite = new ToastComposite();

var toastLevel = null;
function ToastLevel() {
    this.success = 'success';
    this.failure = 'failure';
    this.information = 'information';
}; toastLevel = new ToastLevel();