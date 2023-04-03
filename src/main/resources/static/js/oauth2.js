// Во многих фреймфорках или библиотеках - методы для работы с OAuth2 уже готовые и не нужно будет их писать вручную
// В этом проекте мы все делаем вручную, чтобы вы лучше поняли весь алгоритм действий


// ALG - используются как параметры в разных методах шифрования, где-то с тире, где-то без тире
const SHA_256 = "SHA-256"


// запускаем цикл действий для grant type = PKCE (Proof Key for Code Exchange), который хорошо подходит для JS приложений в браузере
// https://www.rfc-editor.org/rfc/rfc7636
function initValues() {

    // нужен только для первого запроса (авторизация), чтобы клиент убедился, что ответ от AuthServer (после авторизации) пришел именно на его нужный запрос
    // защита от CSRF атак
    var state = generateState(30);
    document.getElementById("originalState").innerHTML = state;
    console.log("state = " + state)


    var codeVerifier = generateCodeVerifier();
    document.getElementById("codeVerifier").innerHTML = codeVerifier;
    console.log("codeVerifier = " + codeVerifier);

    // реактивный код - реакция не выполнения асинхронной функции
    generateCodeChallenge(codeVerifier).then(codeChallenge => {

        console.log("codeChallenge = " + codeChallenge);

    });

}

// https://www.rfc-editor.org/rfc/rfc7636.html#page-8
// в реальных проектах эти функции скорее всего уже реализованы в библиотеке и вы просто вызывает эту функцию
function generateCodeVerifier() {
    var randomByteArray = new Uint8Array(43);
    window.crypto.getRandomValues(randomByteArray);
    return base64urlencode(randomByteArray); // формат Base64 на основе массива байтов

    // про Uint8Array https://learn.javascript.ru/arraybuffer-binary-arrays

}


// преобразование массива байтов в формат текстовый формат Base64
// https://ru.wikipedia.org/wiki/Base64
function base64urlencode(sourceValue) {
    var stringValue = String.fromCharCode.apply(null, sourceValue);
    var base64Encoded = btoa(stringValue);
    var base64urlEncoded = base64Encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return base64urlEncoded;
}


// зачем нужен state - чтобы на втором шаге будем сравнивать его со значением от AuthServer
// тем самым убедимся, что ответ пришел именно на наш запрос
function generateState(length) {

    // генерим случайные символы из англ алфавита
    var state = "";
    var alphaNumericCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var alphaNumericCharactersLength = alphaNumericCharacters.length;
    for (var i = 0; i < length; i++) {
        state += alphaNumericCharacters.charAt(Math.floor(Math.random() * alphaNumericCharactersLength));
    }

    return state;
}


// https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
// В реальных проектах эти функции скорее всего уже реализованы в библиотеке и вы просто вызывает эту функцию
async function generateCodeChallenge(codeVerifier) {

    var textEncoder = new TextEncoder('US-ASCII');
    var encodedValue = textEncoder.encode(codeVerifier); // кодируем в массив байтов ранее полученный code_verifier
    var digest = await window.crypto.subtle.digest(SHA_256, encodedValue);
    // поддержка в браузерах функции шифрования https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle

    return base64urlencode(Array.from(new Uint8Array(digest)));  // Base64 формат на основе хеш-функции, которая применятся на codeVerifier

}
