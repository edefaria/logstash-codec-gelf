require "logstash/codecs/base"
require "logstash/util/charset"
require "logstash/json"
require "logstash/namespace"
require "stringio"
require "date"

# GELF codec. This is useful if you want to use logstash
# to output events to graylog2 using for example the
# rabbitmq output.
#
# More information at <http://graylog2.org/gelf#specs>
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
  config :level, :validate => :array, :default => [ "%{severity}", "INFO" ]

  # The GELF facility. Dynamic values like %{foo} are permitted here; this
  # is useful if you need to use a value from the event as the facility name.
  config :facility, :validate => :string, :deprecated => true

  # The GELF line number; this is usually the line number in your program where
  # the log event originated. Dynamic values like %{foo} are permitted here, but the
  # value should be a number.
  config :line, :validate => :string, :deprecated => true

  # The GELF file; this is usually the source code file in your program where
  # the log event originated. Dynamic values like %{foo} are permitted here.
  config :file, :validate => :string, :deprecated => true

  # Ship metadata within event object? This will cause logstash to ship
  # any fields in the event (such as those created by grok) in the GELF
  # messages.
  config :ship_metadata, :validate => :boolean, :default => false

  # Ship tags within events. This will cause logstash to ship the tags of an
  # event as the field _tags.
  config :ship_tags, :validate => :boolean, :default => true

  # Ship timestamp to float epoch
  config :ship_timestamp, :validate => :boolean, :default => true

  # Ignore these fields when ship_metadata is set. Typically this lists the
  # fields used in dynamic values for GELF fields.
  config :ignore_metadata, :validate => :array, :default => [ "@timestamp", "@version", "severity", "host", "source_host", "source_path", "short_message" ]

  # The GELF custom field mappings. GELF supports arbitrary attributes as custom
  # fields. This exposes that. Exclude the `_` portion of the field name
  # e.g. `custom_fields => ['foo_field', 'some_value']
  # sets `_foo_field` = `some_value`
  config :custom_fields, :validate => :hash, :default => {}

  # The GELF full message. Dynamic values like %{foo} are permitted here.
  config :full_message, :validate => :string, :default => "%{message}"

  # The GELF short message field name. If the field does not exist or is empty,
  # the event message is taken instead.
  config :short_message, :validate => :string, :default => "short_message"

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
    @gelf_version = "1.0"
    @converter = LogStash::Util::Charset.new(@charset)
    @converter.logger = @logger
  end # register

  public
  def decode(data)
    data = @converter.convert(data)
    begin
      yield LogStash::Event.new(LogStash::Json.load(data))
    rescue LogStash::Json::ParserError => e
      @logger.info("JSON parse failure. Falling back to plain-text", :error => e, :data => data)
      yield LogStash::Event.new("message" => data, "tags" => ["_jsonparsefailure"])
    end
  end # def decode

  public
  def encode(event)
    @logger.debug(["encode(event)", event])
    event["version"] = @gelf_version;

    event["short_message"] = event["message"]
    if event[@short_message]
      v = event[@short_message]
      short_message = (v.is_a?(Array) && v.length == 1) ? v.first : v
      short_message = short_message.to_s
      if !short_message.empty?
        event["short_message"] = short_message
      end
    end

    event["full_message"] = event.sprintf(@full_message)

    event["host"] = event.sprintf(@sender)

    # deprecated fields
    event["facility"] = event.sprintf(@facility) if @facility
    event["file"] = event.sprintf(@file) if @file
    event["line"] = event.sprintf(@line) if @line
    event["line"] = event["line"].to_i if event["line"].is_a?(String) and event["line"] === /^[\d]+$/

    if @ship_metadata
      event.to_hash.each do |name, value|
        next if value == nil
        next if name == "message"

        # Trim leading '_' in the data
        name = name[1..-1] if name.start_with?('_')
        name = "_id" if name == "id"  # "_id" is reserved, so use "__id"
        if !value.nil? and !@ignore_metadata.include?(name)
          if value.is_a?(Array)
            event["_#{name}"] = value.join(', ')
          elsif value.is_a?(Hash)
            value.each do |hash_name, hash_value|
              event["_#{name}_#{hash_name}"] = hash_value
            end
          else
            # Non array values should be presented as-is
            # https://logstash.jira.com/browse/LOGSTASH-113
            event["_#{name}"] = value
          end
        end
      end
    end

    if @ship_timestamp
      event["timestamp"] = DateTime.parse(event["timestamp"]).to_time.to_f.to_s if !event["timestamp"].nil?
    end

    if @ship_tags
      if event["tags"].is_a?(Array)
        m["_tags"] = event["tags"].join(', ')
      else
        m["_tags"] = event["tags"]
      end
    end

    if @custom_fields
      @custom_fields.each do |field_name, field_value|
        event["_#{field_name}"] = field_value unless field_name == 'id'
      end
    end

    # Probe severity array levels
    level = nil
    if @level.is_a?(Array)
      @level.each do |value|
        parsed_value = event.sprintf(value)
        next if value.count('%{') > 0 and parsed_value == value

        level = parsed_value
        break
      end
    else
      level = event.sprintf(@level.to_s)
    end
    event["level"] = (@level_map[level.to_s.downcase] || level).to_i

    @on_event.call(event, event.to_json)
  end # def encode
end # class LogStash::Codecs::Gelf
