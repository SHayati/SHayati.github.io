var CryptoJS = require('crypto-js');
var elliptic = require('elliptic');
var EC = elliptic.ec;
var ec = new EC('secp256k1');


angular.module('cryptoApp', [])
    .controller('CryptoController', ['$scope', function ($scope) {
        // Import elliptic library
        var EC = elliptic.ec;
        var ec = new EC('secp256k1');

        // Section 1: SHA256
        $scope.computeSHA256 = function () {
            $scope.shaOutput = CryptoJS.SHA256($scope.shaInput).toString();
        };

        // Section 2: ECDSA Key Pair
        $scope.generateKeys = function () {
            var keys = ec.genKeyPair();
            $scope.ecdsaPrivate = keys.getPrivate('hex');
            $scope.ecdsaPublic = keys.getPublic('hex');
        };

        // Section 3: ECDSA Digital Signature
        $scope.digitalSignature = function () {
            var privateKey = ec.keyFromPrivate($scope.ecdsaVerifyPrivate);
            var msgHash = CryptoJS.SHA256($scope.ecdsaVerifyMessage);
            var signature = privateKey.sign(msgHash.toString(), 'hex');
            //$scope.ecdsaVerifySignatureR = signature.r.toString(16);
            //$scope.ecdsaVerifySignatureS = signature.s.toString(16);
            $scope.ecdsaVerifySignature = signature.r.toString() + '\n' + signature.s.toString();
        };

        // Section 5: ECDSA Digital Signature Verification
        $scope.verifySignature = function () {
            var publicKey = ec.keyFromPublic($scope.ecdsaVerifyPublic, 'hex');
            var msgHash = CryptoJS.SHA256($scope.ecdsaVerifyMessage);
            //var signature = { r: $scope.ecdsaVerifySignatureR, s: $scope.ecdsaVerifySignatureS };
            var aa = $scope.ecdsaVerifySignature.split('\n');
            if (aa.length != 2) {
                $scope.ecdsaVerifyResult =  'Invalid Signature';
                $scope.ecdsaVerifyResultColor =  'red';
                return;
            }
            var signature = { r: $scope.ecdsaVerifySignature.split('\n')[0], s: $scope.ecdsaVerifySignature.split('\n')[1] };
            $scope.ecdsaVerifyResult = publicKey.verify(msgHash.toString(), signature) ? 'Valid Signature' : 'Invalid  Signature';
            $scope.ecdsaVerifyResultColor = $scope.ecdsaVerifyResult === 'Valid Signature' ? 'green' : 'red';
        };
    }]);
