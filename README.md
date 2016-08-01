# Signatures - Length extension attacks in Burp Suite

Burp Suite extension to perform hash length extension attacks on weak signature mechanisms.

### Use cases

* [Cryptopals](https://cryptopals.com/sets/4/challenges/29)
* [Stripe CTF](https://github.com/stripe-ctf/stripe-ctf-2.0/tree/master/levels/7)
* [My own vulnerable app](https://github.com/vergl4s/cheese-selection)

### Examples

Signatures tabs.

![Signatures tab](img/img1.png)

Extension-generated Intruder payloads will be available after messages and hashes are generated on the Signatures tab. **Remember to disable URL-encoding for messages (as below).**

![Signatures payloads](img/img2.png)

Attack results.

![Attack results](img/img3.png)

### TODO

* RIPEMD
* Whirlpool
* Tab for HMAC generation
* Fix copy message button when padding has line breaks
