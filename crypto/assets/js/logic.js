﻿var CryptoJS = require('crypto-js');
var elliptic = require('elliptic');
var EC = elliptic.ec;
var ec = new EC('secp256k1');


angular.module('cryptoApp', [])
    .controller('CryptoController', ['$scope', '$timeout', function ($scope, $timeout) {
        // Import elliptic library
        var EC = elliptic.ec;
        var ec = new EC('secp256k1');

        var content = {
            en: {
                title: 'Cryptocurrency Web App',
                h1: 'Cryptocurrency Algorithms',
                section1: {
                    h2: 'SHA256',
                    p: 'Enter text to compute its SHA256 hash.',
                    label1: 'Input:',
                    button: 'Compute SHA256',
                    label2: 'Output:'
                },
                section2: {
                    h2: 'ECDSA Key Pair',
                    p: 'Generate a pair of ECDSA keys. These keys are called private and public keys. Transaction requests on the network are digitally signed by private key. The actual identity of the person who has signed the transaction can later be verified by the public. The public key also provides the Bitcoin address. For simplicity public key can be understood as an account number and the validator of your messages in the public while the private key can serve as the password. Thus you can share the public key with the public, but you must keep your private key, of course private and strictly avoid revealing that.',
                    button: 'Generate Keys',
                    label1: 'Private Key:',
                    label2: 'Public Key:',
                    bitcoinAddress: 'Bitcoin address generated by pulblic key (Account number): '
                },
                section3: {
                    h2: 'ECDSA Digital Signature Verification',
                    p: 'Verify a digital signature using ECDSA keys. Expose your public key to the public.',
                    label1: 'Public Key:',
                    subsection: {
                        h3: 'Digitally sign a message:',
                        p: 'Write down a message you would like to sign it. Try to write down an imaginary transaction like you want send 1 satoshi (0.00000001 BTC) from your account to another account:',
                        label1: 'Message:',
                        label2: 'Private Key:',
                        p2: 'Here is the digital signature of the message signed by the previous private key:',
                        label3: 'Digital Signature:'
                    },
                    h3: 'Verify the digital signature using public key:',
                    p2: 'The only person who knows the private key is you and thus the signature will be valid if it is signed by you. This is why you have to keep the private key secure and avoid revealing it to others. Now we will verify the message and its signature against the exposed public key. The signature will be verified only if it is signed by the correct private key:',
                    button: 'Verify Signature',
                    label4: 'Verification Result:'
                },
                p: 'All the transactions on the blockchain are signed by their owners. You are the owner of your cryptocurrency and you are the only one who can sign a check to spend it so long as you have your private key kept secret.'
            },
            fa: {
                title: 'برنامه وب ارز دیجیتال',
                h1: 'الگوریتم‌های ارز دیجیتال',
                section1: {
                    h2: 'SHA256',
                    p: 'متن را وارد کنید تا هش SHA256 آن محاسبه شود.',
                    label1: 'ورودی:',
                    button: 'محاسبه SHA256',
                    label2: 'خروجی:'
                },
                section2: {
                    h2: 'جفت کلید ECDSA',
                    p: 'یک جفت کلید ECDSA تولید کنید. این کلیدها به عنوان کلیدهای خصوصی و عمومی شناخته می‌شوند. درخواست‌های تراکنش در شبکه با کلید خصوصی امضا می‌شوند. هویت واقعی فردی که تراکنش را امضا کرده است بعداً با کلید عمومی قابل تأیید است. کلید عمومی همچنین آدرس بیت‌کوین را فراهم می‌کند. برای سادگی، کلید عمومی می‌تواند به عنوان شماره حساب و تأییدکننده پیام‌های شما در عموم درک شود، در حالی که کلید خصوصی می‌تواند به عنوان رمز عبور عمل کند. بنابراین شما می‌توانید کلید عمومی را با عموم به اشتراک بگذارید، اما باید کلید خصوصی خود را به طور خصوصی نگه دارید و از افشای آن خودداری کنید.',
                    button: 'تولید کلیدها',
                    label1: 'کلید خصوصی:',
                    label2: 'کلید عمومی:',
                    bitcoinAddress: 'آدرس بیت‌کوین تولید شده توسط کلید عمومی (شماره حساب): '
                },
                section3: {
                    h2: 'تأیید امضای دیجیتال ECDSA',
                    p: 'یک امضای دیجیتال را با استفاده از کلیدهای ECDSA تأیید کنید. کلید عمومی خود را به عموم نمایش دهید.',
                    label1: 'کلید عمومی:',
                    subsection: {
                        h3: 'امضای دیجیتال یک پیام:',
                        p: 'پیامی را که می‌خواهید امضا کنید بنویسید. سعی کنید یک تراکنش خیالی بنویسید، مثلاً می‌خواهید 1 ساتوشی (0.00000001 بیت‌کوین) از حساب خود به حساب دیگری بفرستید:',
                        label1: 'پیام:',
                        label2: 'کلید خصوصی:',
                        p2: 'در اینجا امضای دیجیتال پیام امضا شده توسط کلید خصوصی قبلی آمده است:',
                        label3: 'امضای دیجیتال:'
                    },
                    h3: 'تأیید امضای دیجیتال با استفاده از کلید عمومی:',
                    p2: 'امضای دیجیتال توسط کلید خصوصی کد می شود و تنها کسی که کلید خصوصی را می‌داند شما هستید. بنابراین امضای دیجیتال معتبر خواهد بود اگر توسط شما امضا شده باشد. به همین دلیل شما باید کلید خصوصی را ایمن نگه دارید و از افشای آن به دیگران خودداری کنید. اکنون صحت امضای دیجیتال الصاق شده به پیام را صحت سنجی می کنیم. به این منظور آن را در مقابل کلید عمومی که اعتبارسنجی می کنیم. امضای صورت گرفته فقط در صورتی تأیید می‌شود که با کلید خصوصی صحیح امضا شده باشد:',
                    button: 'تأیید امضا',
                    label4: 'نتیجه تأیید:'
                },
                p: 'تمام تراکنش‌ها در بلاکچین توسط صاحبانشان امضا می‌شوند. مادامی که کلید خصوصی را نزد خود به صورت مخفی نگه دارید شما صاحب ارز دیجیتال خود و تنها کسی هستید که می‌تواند یک چک برای خرج کردن آن امضا کند.'
            }
        };

        // Set default language
        $scope.content = content.en;

        // Function to change language
        $scope.setLanguage = function (lang) {
            $scope.content = content[lang];
            $scope.language = lang;
            $scope.direction = lang === 'fa' ? 'rtl' : 'ltr';
        };

        // Set default language
        $scope.setLanguage('en');

        // Section 1: SHA256
        $scope.computeSHA256 = function () {
            $scope.shaOutput = CryptoJS.SHA256($scope.shaInput).toString();
        };

        // Section 2: ECDSA Key Pair
        $scope.generateKeys = function () {
            var keys = ec.genKeyPair();
            $scope.ecdsaPrivate = keys.getPrivate('hex');
            $scope.ecdsaPublic = keys.getPublic('hex');

            // Hash the public key
            const publicKeyHash = CryptoJS.RIPEMD160(CryptoJS.SHA256($scope.ecdsaPublic).toString()).toString();

            // This is your Bitcoin address (account number)
            $scope.bitcoinAddress = `0x${publicKeyHash}`;

        };

        // Section 3: ECDSA Digital Signature
        $scope.digitalSignature = function () {
            var privateKey = ec.keyFromPrivate($scope.ecdsaVerifyPrivate);
            var msgHash = CryptoJS.SHA256($scope.ecdsaVerifyMessage);
            var signature = privateKey.sign(msgHash.toString(), 'hex');
            //$scope.ecdsaVerifySignatureR = signature.r.toString(16);
            //$scope.ecdsaVerifySignatureS = signature.s.toString(16);
            $scope.ecdsaVerifySignature = signature.r.toString(16) + '\n' + signature.s.toString(16);
        };

        $scope.$watchGroup(['ecdsaVerifyMessage', 'ecdsaVerifyPrivate'], function (newValues, oldValues) {
            if (newValues !== oldValues) {
                $timeout.cancel($scope.digitalSignaturePromise); // Cancel previous timeout if it exists
                $scope.digitalSignaturePromise = $timeout($scope.digitalSignature, 1000); // Start a new timeout
            }
        });
        // Section 5: ECDSA Digital Signature Verification
        $scope.verifySignature = function () {
            try {

                var publicKey = ec.keyFromPublic($scope.ecdsaVerifyPublic, 'hex');
                var msgHash = CryptoJS.SHA256($scope.ecdsaVerifyMessage);
                //var signature = { r: $scope.ecdsaVerifySignatureR, s: $scope.ecdsaVerifySignatureS };
                var aa = $scope.ecdsaVerifySignature.split('\n');
                if (aa.length != 2) {
                    $scope.ecdsaVerifyResult = 'Invalid Signature';
                    $scope.ecdsaVerifyResultColor = 'red';
                    return;
                }
                var signature = { r: $scope.ecdsaVerifySignature.split('\n')[0], s: $scope.ecdsaVerifySignature.split('\n')[1] };
                $scope.ecdsaVerifyResult = publicKey.verify(msgHash.toString(), signature) ? 'Valid Signature' : 'Invalid  Signature';
                $scope.ecdsaVerifyResultColor = $scope.ecdsaVerifyResult === 'Valid Signature' ? 'green' : 'red';
            } catch (error) {
                $scope.ecdsaVerifyResult = 'Invalid Signature';
                $scope.ecdsaVerifyResultColor = 'red';
            }

        };
    }]);
