# Firebase ID Token verifier
Code snippet to show how to verify Firebase ID tokens using **Ruby**.

**FirebaseIDTokenVerifier** class holds 2 methods: **encode** and **decode**.

The **encode** method is written just for testing purpose - I have other project where I use this method in my tests to generate a test JWT token and use it in further tests.

The **decode** method is actually what you need. It helps you to verify your Firebase ID token according to Firebase validation rules:
[Verify ID tokens using a third-party JWT library](https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library)

# License
MIT