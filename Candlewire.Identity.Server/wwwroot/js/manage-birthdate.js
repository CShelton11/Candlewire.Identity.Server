var birthdateComposite = null;
function BirthdateComposite() {
    this.configure = function () {
        $('.birth-date-field').datepicker({
            format: 'm/d/yyyy',
            autoclose: true
        });

        $('.birth-date-field').click(function (e) {
            $('.birth-date-hidden').focus();
        });

        $(document).on("contextmenu", ".birth-date-field", function (e) {
            $('.birth-date-hidden').focus();
            return false;
        });
    }

    $(document).ready(function () {
        birthdateComposite.configure();
    });

}; birthdateComposite = new BirthdateComposite();