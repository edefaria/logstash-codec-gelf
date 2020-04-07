## 0.4
  - Clone event in encode (if use multiple output the event is not modified).
  - Fix decode to be stream (useable in logstash-input-kafka).
  - Add check for kafka limitation in flatten gelf and ES field lenght.
  - Add optimisation in flatten gelf (does leading underscore and pre-calculate size of each field).
  - Fix tags (do not flatten tags fields and transform it into string).
  - Add ovh ldp transformation field based on ruby class variable.
  - Fix some corner case in timestamp transformation.
  - Cleanup code/fix.

## 0.3
  - Migration to logstash plugin-api 2.0 (Logstash >= 2.4.0).
  - Write a function to flatten recursively the gelf (transform nested object).
  - Add check on value size (ES limitation) and max field generation during flatten.
  - Add more check on timestamp.
  - Transform empty message to be valid.

## 0.2
  - Switch to gelf protocol 1.1 to remove level field and global better on gelf protocol generation.

# 0.1.1
  - Update to Logstash 2.0.0.

## 0.1
  - Code based on logstash-input-gelf, logstash-output-gelf and codec-json-line.
  - Supporting Decoding/Encoding (input/output).
  - Support framing/delimiter for tcp plugin with option delimiter => "\x00".
