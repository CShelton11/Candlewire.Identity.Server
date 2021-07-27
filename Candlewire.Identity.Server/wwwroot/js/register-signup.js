var signupComposite = null;

function SignupComposite() {
    this.configure = function () {  // Configure page composite
        $('.birth-date-field').datepicker({
            format: 'm/d/yyyy',
            autoclose: true
        });

        $('form').on('keyup change paste', 'input, select, textarea', function () {
            signupComposite.statify();
        });

        $('.password-field').keyup(function () {
            signupComposite.measure($(this).val());
            signupComposite.compare($(this).val(), $('.confirm-field').val());
        });

        $('.confirm-field').keyup(function () {
            signupComposite.compare($(this).val(), $('.password-field').val());
        });

        $(".password-toggle a").on('click', function (event) {
            event.preventDefault();
            if ($('.password-toggle input').attr("type") == "text") {
                $('.password-toggle input').attr('type', 'password');
                $('.password-toggle i').addClass("fa-eye-slash");
                $('.password-toggle i').removeClass("fa-eye");
            } else if ($('.password-toggle input').attr("type") == "password") {
                $('.password-toggle input').attr('type', 'text');
                $('.password-toggle i').removeClass("fa-eye-slash");
                $('.password-toggle i').addClass("fa-eye");
            }
        });
    }

    this.load = function () {   // Composite load events

    }

    this.statify = function () {  // Monitor form state and adjust controls accordingly

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
        signupComposite.configure();
        signupComposite.load();
    });
}; signupComposite = new SignupComposite();