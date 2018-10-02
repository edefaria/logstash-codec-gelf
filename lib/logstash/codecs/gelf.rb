require "logstash/codecs/base"
require "logstash/util/charset"
require "logstash/util/buftok"
require "logstash/json"
require "logstash/namespace"
require "stringio"
require "date"
require "time"

# GELF codec. This is useful if you want to use logstash
# to input or output events to graylog2 using for example:
# - logstash-input-tcp
# - logstash-output-kafka
# - logstash-output-tcp
# More information at gelf spec: <http://graylog2.org/gelf#specs>
class LogStash::Codecs::Gelf < LogStash::Codecs::Base
  config_name "gelf"

  milestone 1

  # Allow overriding of the gelf 'sender' field. This is useful if you
  # want to use something other than the event's source host as the
  # "sender" of an event. A common case for this is using the application name
  # instead of the hostname.
  config :sender, :validate => :string, :default => "%{host}"

  # The GELF message level. Dynamic values like %{level} are permitted here;
  # useful if you want to parse the 'log level' from an event and use that
  # as the gelf level/severity.
  #
  # Values here can be integers [0..7] inclusive or any of
  # "debug", "info", "warn", "error", "fatal" (case insensitive).
  # Single-character versions of these are also valid, "d", "i", "w", "e", "f",
  # "u"
  # The following additional severity_labels from logstash's  syslog_pri filter
  # are accepted: "emergency", "alert", "critical",  "warning", "notice", and
  # "informational"
  config :level, :validate => :array, :default => [ "%{severity}" ]

  # Ship metadata within event object? This will cause logstash to ship
  # any fields in the event (such as those created by grok) in the GELF
  # messages.
  config :ship_metadata, :validate => :boolean, :default => true

  # Ship tags within events. This will cause logstash to ship the tags of an
  # event as the field _tags.
  config :ship_tags, :validate => :boolean, :default => true

  # Ship timestamp to float epoch
  config :ship_timestamp, :validate => :boolean, :default => true

  # Ignore these fields when ship_metadata is set. Typically this lists the
  # fields used in dynamic values for GELF fields.
  config :ignore_metadata, :validate => :array, :default => [ "@timestamp", "version", "level", "host", "timestamp", "short_message", "full_message", "facility", "line", "file" ]

  # The GELF custom field mappings. GELF supports arbitrary attributes as custom
  # fields. This exposes that. Exclude the `_` portion of the field name
  # e.g. `custom_fields => ['foo_field', 'some_value']
  # sets `_foo_field` = `some_value`
  config :custom_fields, :validate => :hash, :default => {}

  # Change the delimiter that separates events
  config :delimiter, :validate => :string

  # The GELF full message field name. If option is true and if the field is not already set,
  # set the full_message field value at the value of the field "message".
  config :full_message, :validate => :boolean, :default => false

  # The GELF short message field name. If the field does not exist or is empty,
  # the event message is taken instead.
  config :short_message, :validate => :string, :default => "short_message"

  # The GELF short message default message, Fix the short_message by this value
  # when event message does not exist or is empty.
  config :default_message, :validate => :string, :default => "-"

  # The character encoding used in this codec. Examples include "UTF-8" and
  # "CP1252".
  #
  # JSON requires valid UTF-8 strings, but in some cases, software that
  # emits JSON does so in another encoding (nxlog, for example). In
  # weird cases like this, you can set the `charset` setting to the
  # actual encoding of the text and Logstash will convert it for you.
  #
  # For nxlog users, you may to set this to "CP1252".
  config :charset, :validate => ::Encoding.name_list, :default => "UTF-8"

  # Whether or not to remap the GELF message fields to Logstash event fields or
  # leave them intact.
  #
  # Remapping converts the following GELF fields to Logstash equivalents:
  #
  # * `full\_message` becomes `event.get("message")`.
  # * if there is no `full\_message`, `short\_message` becomes `event.get("message")`.
  config :remap, :validate => :boolean, :default => true

  # Whether or not to remove the leading `\_` in GELF fields or leave them
  # in place during decode.
  #
  # e.g. `\_foo` becomes `foo`
  #
  config :strip_leading_underscore, :validate => :boolean, :default => true

  # Add the leading `\_` in GELF fields or leave them
  # in place during encode.
  #
  # e.g. `foo` becomes `\_foo`
  #
  config :add_leading_underscore, :validate => :boolean, :default => true

  RECONNECT_BACKOFF_SLEEP = 5
  TIMESTAMP_GELF_FIELD = "timestamp".freeze
  SOURCE_HOST_FIELD = "source_host".freeze
  MESSAGE_FIELD = "message"
  TAGS_FIELD = "tags"
  PARSE_FAILURE_TAG = "_jsonparsefailure"
  PARSE_FAILURE_LOG_MESSAGE = "JSON parse failure. Falling back to plain-text"

  public
  def register
    @logger.info("Starting gelf codec...")
    # these are syslog words and abbreviations mapped to RFC 5424 integers
    # and logstash's syslog_pri filter
    @level_map = {
      "debug" => 7, "d" => 7,
      "info" => 6, "i" => 6, "informational" => 6,
      "notice" => 5, "n" => 5,
      "warn" => 4, "w" => 4, "warning" => 4,
      "error" => 3, "e" => 3,
      "critical" => 2, "c" => 2,
      "alert" => 1, "a" => 1,
      "emergency" => 0, "e" => 0,
    }
    # The version of GELF that we conform to
    @gelf_version = "1.1"
    if @delimiter
      # Fix some control character
      case @delimiter
        when "\\n"  # end of line character
          @delimiter = "\n"
        when "\\0", "\\x00", "\\u0000"  # nul character
          @delimiter = "\x00"
        when "\\t"  # tab character
          @delimiter = "\t"
      end
      @buffer = FileWatch::BufferedTokenizer.new(@delimiter)
    end
    @converter = LogStash::Util::Charset.new(@charset)
    @converter.logger = @logger
  end # register

  public
  def decode_gelf(event)
    @logger.debug("event", :event => event)
    unless event.nil?
      if (gelf_timestamp = event.get(TIMESTAMP_GELF_FIELD)).is_a?(Numeric)
        event.timestamp = coerce_timestamp(gelf_timestamp)
        event.remove(TIMESTAMP_GELF_FIELD)
      end
      remap_gelf(event) if @remap
      strip_leading_underscore(event) if @strip_leading_underscore
    end
    event
  end # decode_gelf

  public
  def decode(data, &block)
    @logger.debug("decode(data)", :data => data)
    if @delimiter
      @buffer.extract(data).each do |line|
        @logger.debug("decode(line)", :line => line)
        yield decode_gelf(parse(@converter.convert(line), &block))
      end
    else
      # data received.  Remove trailing \0
      data[-2] == "\u0000" && data = data[0...-2]
      data[-1] == "\u0000" && data = data[0...-1]
      yield decode_gelf(parse(@converter.convert(data), &block))
    end
  end # def decode

  public
  def encode(event)
    @logger.debug("encode(event)", :event => event)
    event.set("version", @gelf_version)

    if event.get("message")
      event.set("short_message", event.get("message")) if event.get("short_message").nil?
    end
    if event.get(@short_message)
      v = event.get(@short_message)
      short_message = (v.is_a?(Array) && v.length == 1) ? v.first : v
      short_message = short_message.to_s
      if !short_message.empty?
        event.set("short_message", short_message)
      else
        event.set("short_message", @default_message)
      end
    else
      event.set("short_message", @default_message)
    end

    if @full_message
      event.set("full_message", event.get("message")) if event.get("full_message").nil?
    end

    event.set("host", event.sprintf(@sender))

    if @ship_tags
      unless event.get("tags").nil?
        if event.get("tags").is_a?(Array)
          event.set("_tags", event.get("tags").join(', '))
        else
          event.set("_tags", event.get("tags"))
        end
        event.remove("tags")
      end
    end
    add_leading_underscore(event) if @add_leading_underscore

    if @ship_timestamp
      if event.get("timestamp").nil?
        if !event.get('@timestamp').nil?
          begin
            dt = DateTime.parse(event.get("@timestamp").to_iso8601).to_time.to_f
          rescue StandardError
            @logger.debug("Cannot convert @timestamp", :timestamp => event.get("@timestamp"))
            dt = DateTime.now.to_time.to_f
          end
          event.set("timestamp", dt)
        end
      else
        begin
          dt = Time.at(Float(event.get("timestamp"))).to_f
        rescue StandardError
          begin
            dt = DateTime.parse(event.get("timestamp").to_iso8601).to_time.to_f
          rescue StandardError
            @logger.debug("Cannot convert timestamp", :timestamp => event.get("timestamp"))
            dt = DateTime.now.to_time.to_f
          end
        end
        event.set("timestamp", dt)
      end
    end

    if @custom_fields
      @custom_fields.each do |field_name, field_value|
        event.set("_#{field_name}", field_value) unless field_name == 'id'
      end
    end

    # Probe levels/severity
    if event.get("level")
      unless (0..7) === event.get("level")
        begin
          event.set("level", (@level_map[event.get("level").to_s.downcase] || event.get("level")).to_i)
        rescue StandardError
          event.set("level", 1)
        end
      end
    elsif event.get("severity")
      begin
        event.set("level", (@level_map[event.get("severity").to_s.downcase] || event.get("severity")).to_i)
      rescue StandardError
        event.set("level", 1)
      end
    end

    if @delimiter
      @on_event.call(event, "#{event.to_json}#{@delimiter}")
    else
     @on_event.call(event, event.to_json)
    end
  end # def encode

  private
  # transform a given timestamp value into a proper LogStash::Timestamp, preserving microsecond precision
  # and work around a JRuby issue with Time.at loosing fractional part with BigDecimal.
  # @param timestamp [Numeric] a Numeric (integer, float or bigdecimal) timestampo representation
  # @return [LogStash::Timestamp] the proper LogStash::Timestamp representation
  def coerce_timestamp(timestamp)
    # bug in JRuby prevents correcly parsing a BigDecimal fractional part, see https://github.com/elastic/logstash/issues/4565
    timestamp.is_a?(BigDecimal) ? LogStash::Timestamp.at(timestamp.to_i, timestamp.frac * 1000000) : LogStash::Timestamp.at(timestamp)
  end # def coerce_timestamp

  def remap_gelf(event)
    if event.get("full_message") && !event.get("full_message").empty?
      event.set("message", event.get("full_message").dup)
      event.remove("full_message")
      if event.get("short_message") == event.get("message")
        event.remove("short_message")
      end
    elsif event.get("short_message")  && !event.get("short_message").empty?
      event.set("message", event.get("short_message").dup)
      event.remove("short_message")
    end
    if event.get("version")
      event.remove("version")
    end
    if event.get("timestamp")
      event.remove("timestamp")
    end
  end # def remap_gelf

  def strip_leading_underscore(event)
     # Map all '_foo' fields to simply 'foo'
     event.to_hash.keys.each do |key|
       next unless key.is_a?(String)
       next unless key[0,1] == "_"
       key = "_id" if key == "__id" # "_id" is reserved, so set back to "id"
       event.set(key[1..-1], event.get(key))
       event.remove(key)
     end
  end # def strip_leading_underscores

  def add_leading_underscore(event)
     event.to_hash.keys.each do |key|
       next unless key.is_a?(String)
       name = key
       value = event.get(key)
       next if name == "message"

       # Trim leading '_' in the data
       name = name[1..-1] if name.start_with?('_')
       name = "_id" if name == "id"  # "_id" is reserved, so use "__id"

       if !@ignore_metadata.include?(name)
         if @ship_metadata
           if value.nil?
             event.set("_#{name}", nil)
           elsif value.is_a?(Array)
             event.set("_#{name}", value.join(', ').to_s)
           elsif value.is_a?(Hash)
             value.each do |hash_name, hash_value|
               if hash_value.is_a? Numeric
                 event.set("_#{name}_#{hash_name}", hash_value)
               else
                 event.set("_#{name}_#{hash_name}", hash_value.to_s)
               end
             end
           else
             if value.is_a? Numeric
               event.set("_#{name}", value)
             else
               event.set("_#{name}", value.to_s)
             end
           end
           event.remove(name)
         else
           event.set("_#{name}", value)
           event.remove(name)
         end
       end
     end
     @logger.debug("after (add_leading_underscore)", :event => event)
  end # def add_leading_underscore

  # from_json_parse uses the Event#from_json method to deserialize and directly produce events
  def from_json_parse(json, &block)
    LogStash::Event.from_json(json).each { |event| event }
  rescue LogStash::Json::ParserError => e
    @logger.warn("JSON parse error, original data now in message field", :error => e, :data => json)
    LogStash::Event.new("message" => json, "tags" => ["_jsonparsefailure"])
  end # def from_json_parse

  # legacy_parse uses the LogStash::Json class to deserialize json
  def legacy_parse(json, &block)
    # ignore empty/blank lines which LogStash::Json#load returns as nil
    o = LogStash::Json.load(json)
    LogStash::Event.new(o) if o
  rescue LogStash::Json::ParserError => e
    @logger.warn("JSON parse error, original data now in message field", :error => e, :data => json)
    LogStash::Event.new("message" => json, "tags" => ["_jsonparsefailure"])
  end # def legacy_parse

  # keep compatibility with all v2.x distributions. only in 2.3 will the Event#from_json method be introduced
  # and we need to keep compatibility for all v2 releases.
  alias_method :parse, LogStash::Event.respond_to?(:from_json) ? :from_json_parse : :legacy_parse

end # class LogStash::Codecs::Gelf
