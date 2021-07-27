var passwordComposite = null;

function PasswordComposite() {
    this.configure = function () {  // Configure page composite
        $('.password-field').keyup(function () {
            passwordComposite.measure($(this).val());
            passwordComposite.compare($(this).val(), $('.confirm-field').val());
        });

        $('.confirm-field').keyup(function () {
            passwordComposite.compare($(this).val(), $('.password-field').val());
        });

        $(".password-toggle a").on('click', function (event) {
            event.preventDefault();
            if ($(this).parent().parent().find('input').attr("type") == "text") {
                $(this).parent().parent().find('input').attr('type', 'password');
                $(this).parent().parent().find('i').addClass("fa-eye-slash");
                $(this).parent().parent().find('i').removeClass("fa-eye");
            } else if ($(this).parent().parent().find('input').attr("type") == "password") {
                $(this).parent().parent().find('input').attr('type', 'text');
                $(this).parent().parent().find('i').removeClass("fa-eye-slash");
                $(this).parent().parent().find('i').addClass("fa-eye");
            }
        });
    }

    this.compare = function (password1, password2) {    // Compare entered passwords
        if ((password1 == '' || password2 == '') || (password1 != password2)) { $('.confirm-image').hide(); }
        else { $('.confirm-image').show(); }
    }

    this.measure = function (password) { // Test password strength
        var strength = 0;
        if (password.length == 0) { strength = 0 }
        else if (password.length < 5) { strength = 1 }
        else {
            if (password.match(/[a-z]+/)) { strength += 1; }
            if (password.match(/[A-Z]+/)) { strength += 1; }
            if (password.match(/[0-9]+/)) { strength += 1; }
            if (password.match(/[$@#&!]+/)) { strength += 1; }
            if (password.length > 10) { strength += 1; }
        }

        $('.password-progress').css('width', (strength * 20).toString() + '%');
        if (strength == 0) { $('.password-strength').html(''); }
        else if (strength <= 3) { $('.password-strength').html('weak'); }
        else if (strength == 4) { $('.password-strength').html('good'); }
        else if (strength == 5) { $('.password-strength').html('strong'); }
    }

    $(document).ready(function () {
        passwordComposite.configure();
    });
}; passwordComposite = new PasswordComposite();