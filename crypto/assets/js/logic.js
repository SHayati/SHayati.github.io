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
        $scope.encryptContent = function () {
            var privateKey = ec.keyFromPrivate($scope.ecdsaEncryptPrivate);
            var msgHash = CryptoJS.SHA256($scope.ecdsaEncryptContent);
            var signature = privateKey.sign(msgHash.toString(), 'hex');
            $scope.encrypted = signature.toDER('hex');
        };

        $scope.decryptContent = function () {
            var publicKey = ec.keyFromPublic($scope.ecdsaDecryptPublic, 'hex');
            var msgHash = CryptoJS.SHA256($scope.ecdsaEncryptContent);
            var signature = { r: $scope.encrypted.slice(0, 64), s: $scope.encrypted.slice(64) };
            $scope.decrypted = publicKey.verify(msgHash.toString(), signature) ? 'Valid' : 'Invalid';
        };
    }]);
