function isValidUrl(input) {

    try {
        new URL(input);
        return true;
    } catch (error) {
        return false;
    }

}

module.exports = {
    isValidUrl
};