# krypty
A simplified module to generate random strings and a simple AES CBC encryption interface.

## Example usage:
```v
mut my_text := 'Hello world! This is an encrypted message! ;)'.bytes()

iv := 'asdfasdfasdfasdf'.bytes() // Must be 16 characters
key := 'asdfasdfasdfasdfasdfasdfasdfasd'.bytes() // Note: Must be 32 Characters. Also `Key` gets overwritten after use for some reason
key2 := 'asdfasdfasdfasdfasdfasdfasdfasd'.bytes()

new_text := krypty.encrypt(my_text, iv, key)
println(new_text.str())
println(krypty.bytes_to_str(krypty.decrypt(new_text, key2)))
```
