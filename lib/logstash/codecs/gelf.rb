require "logstash/codecs/base"
require "logstash/util/charset"
require "logstash/util/buftok"
require "logstash/json"
require "logstash/namespace"
require "date"
require "time"

module Boolean; end
class TrueClass; include Boolean; end
class FalseClass; include Boolean; end

# GELF codec. This is useful if you want to use logstash
# to input or output events to graylog2 using for example:
# - logstash-input-tcp
# - logstash-input-kafka
# - logstash-output-kafka
# - logstash-output-tcp
# More information at gelf spec: <http://graylog2.org/gelf#specs>
class LogStash::Codecs::Gelf < LogStash::Codecs::Base
  config_name "gelf"

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

  # Deflate the record object, this will cause record to be deflate
  # or hash in the record to be more compliance to GELF payload.
  config :ship_metadata, :validate => :boolean, :default => true

  # Ship tags within events. This will cause logstash to ship the tags of an
  # event as the field _tags.
  config :ship_tags, :validate => :boolean, :default => true

  # Ship timestamp to float epoch.
  config :ship_timestamp, :validate => :boolean, :default => true

  # When deflate the record object, add a max number of field on the result.
  # When field number is reached, this forces to transform the remain field as a string,
  # set 0 if you want to disable it.
  config :max_field, :validate => :number, :default => 150

  # Limit character lenght on record field because Elasticsearch has a limit of 255 characters,
  # Limit in character, set 0 if you want to disable it.
  config :max_field_length, :validate => :number, :default => 255

  # Limit string length on record object because Elasticsearch has a limit of 32k,
  # Limit in byte, set 0 if you want to disable it.
  config :max_value_size, :validate => :number, :default => 32766

  # Limit in size the deflate expansion,
  # Limit in byte, set 0 if you want to disable it.
  config :max_metadata_size, :validate => :number, :default => 1015810

  # Keep top Array/Hash value when flatten.
  config :keep_top, :validate => :boolean, :default => true

  # Active ovh ldp convention based on ruby type variable.
  config :ovh_ldp, :validate => :boolean, :default => false

  # List ldp convention to exclude when ovh_ldp is set.
  config :ovh_ldp_convention, :validate => :array, :default => [ "_num", "_double", "_float", "_int", "_long", "_date", "_bool", "_ip", "_geolocation" ]

  # Ignore these fields when ovh_ldp is set.
  config :ignore_ovh_ldp, :validate => :array, :default => [ "host", "short_message", "full_message" ]

  # Ignore these fields when ship_metadata is set.
  config :ignore_metadata, :validate => :array, :default => [ "tags", "version", "level", "timestamp", "facility", "line", "file" ]

  # Ignore these fields when addi the leading `\_` in GELF fields.
  # Typically this lists the fields used in dynamic values for GELF fields.
  config :ignore_leading_underscore, :validate => :array, :default => [ "version", "level", "host", "timestamp", "short_message", "full_message", "facility", "line", "file", "tags" ]

  # The GELF custom field mappings. GELF supports attributes as custom
  # fields. This exposes that. Exclude the `_` portion of the field name
  # Example:
  # `custom_fields` => ['foo_field', 'bar_value']
  # With multiple field/value:
  # `custom_fields` => {
  #   'foo_field' => 'bar_value'
  #   'some_field' => 'some_value'
  # }
  config :custom_fields, :validate => :hash, :default => {}

  # On decoding event, Filter only by the field name_list
  # Example:
  # `filter_fields` => {
  #   'foo_field' => 'bar_value'
  #   'some_field' => ['value1','value2','value3']
  # }
  # if multiple field is passed AND operator is apply on each field
  # if array in value is passed OR operator is apply on each value
  config :filter_fields, :validate => :hash, :default => {}

  # Change the delimiter that separates events.
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

  config :elasticsearch_integrity, :validate => :boolean, :default => true

  TIMESTAMP_GELF_FIELD = "timestamp".freeze
  SOURCE_HOST_FIELD = "source_host".freeze
  TRUE_REGEX = (/^(true|1)$/i).freeze
  FALSE_REGEX = (/^(false|0)$/i).freeze
  PARSE_FAILURE_LOG_MESSAGE = "JSON parse failure. Falling back to plain-text"

  public

  def register
    logger.debug("Starting gelf codec...")
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
      "emergency" => 0,
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
  end # register

  def decode(data, &block)
    logger.debug("decode(data)", :data => data)
    if @delimiter
      @buffer.extract(data).each do |line|
        logger.debug("decode(line)", :line => line)
        parse(@converter.convert(line), &block)
      end
    else
      parse(@converter.convert(data), &block)
    end
  end # def decode

  def encode(event)
    logger.debug("encode(event)", :event => event.to_hash)
    data = event.clone
    gelf_encode(data)
    logger.debug("encode(data)", :data => data.to_hash)
    if @delimiter
      @on_event.call(event, "#{data.to_json}#{@delimiter}")
    else
     @on_event.call(event, data.to_json)
    end
  end # def encode

  def flush(&block)
    remainder = @buffer.flush
    if !remainder.empty?
      parse(@converter.convert(remainder), &block)
    end
  end # def flush

  def gelf_encode(data)
    data.set("version", @gelf_version)
    data.set("host", data.sprintf(@sender))
    if @custom_fields
      @custom_fields.each do |field_name, field_value|
        data.set("#{field_name}", field_value) unless field_name == 'id'
      end
    end

    if data.get("message")
      if data.get("short_message").nil?
        data.set("short_message", data.get("message"))
        data.remove("message")
      elsif data.get("full_message").nil?
        data.set("full_message", data.get("message"))
        data.remove("message")
      end
    end
    if @full_message
      if data.get("full_message").nil?
        data.set("full_message", data.get("short_message").to_s) unless data.get("short_message").empty?
      end
    end
    if data.get("short_message")
      v = data.get("short_message")
      short_message = (v.is_a?(Array) && v.length == 1) ? v.first : v
      short_message = short_message.to_s
      unless short_message.empty?
        data.set("short_message", short_message)
      else
        data.set("short_message", @default_message)
      end
    else
      data.set("short_message", @default_message)
    end

    if @elasticsearch_integrity
      elasticsearch_integrity(data,flatten_gelf(data,keep_top))
    else
      flatten_gelf(data,keep_top)
    end

    if @ship_tags
      if data.get("tags")
        tags =  data.get("tags")
        unless tags.nil?
          if tags.is_a?(Array)
            if tags.size > 1
              data.set("_tags", tags.join(', '))
            else
              data.set("_tags", tags.first.to_s)
            end
          elsif tags.is_a?(String)
            data.set("_tags", tags)
          else
            data.set("_tags", tags.to_s) rescue nil
          end
          data.remove("tags")
        end
      end
    else
      data.remove("tags")
    end

    # Get/Check timestamp valididy
    if @ship_timestamp
      if data.get("timestamp").nil?
        if data.get("_@timestamp").nil?
          dt = DateTime.now.to_time.to_f
        else
          begin
            dt = DateTime.parse(data.get("_@timestamp").to_iso8601).to_time.to_f
          rescue StandardError
            begin
              dt = DateTime.parse(data.get("_@timestamp")).to_time.to_f
            rescue StandardError
              logger.debug("Cannot convert @timestamp", :timestamp => data.get("_@timestamp"))
              dt = DateTime.now.to_time.to_f
            end
          end
        end
      else
        begin
          dt = Time.at(Float(data.get("timestamp"))).to_f
        rescue StandardError
          begin
            dt = DateTime.parse(data.get("timestamp").to_iso8601).to_time.to_f
          rescue StandardError
            begin
              dt = DateTime.parse(data.get("timestamp")).to_time.to_f
            rescue StandardError
              logger.debug("Cannot convert timestamp", :timestamp => data.get("timestamp"))
              dt = DateTime.now.to_time.to_f
            end
          end
        end
      end
      unless dt.is_a?(Numeric)
        dt = DateTime.now.to_time.to_f
      end
      data.set("timestamp", dt)
      data.timestamp = coerce_timestamp(dt)
    end

    # Probe levels/severity
    if data.get("level")
      unless (0..7) === data.get("level")
        begin
          data.set("level", (@level_map[data.get("level").to_s.downcase] || data.get("level")).to_i)
        rescue StandardError
          data.set("level", 1)
        end
      end
    elsif data.get("severity")
      begin
        data.set("level", (@level_map[data.get("severity").to_s.downcase] || data.get("severity")).to_i)
      rescue StandardError
        data.set("level", 1)
      end
    end
  end # def gelf_encode

  private

  # transform a given timestamp value into a proper LogStash::Timestamp, preserving microsecond precision
  # and work around a JRuby issue with Time.at loosing fractional part with BigDecimal.
  # @param timestamp [Numeric] a Numeric (integer, float or bigdecimal) timestampo representation
  # @return [LogStash::Timestamp] the proper LogStash::Timestamp representation
  def coerce_timestamp(timestamp)
    # bug in JRuby prevents correcly parsing a BigDecimal fractional part, see https://github.com/elastic/logstash/issues/4565
    timestamp.is_a?(BigDecimal) ? LogStash::Timestamp.at(timestamp.to_i, timestamp.frac * 1000000) : LogStash::Timestamp.at(timestamp)
  end # def coerce_timestamp

  def decode_gelf(event, &block)
    #event = from_json_parse(event)
    return if event.nil?
    if @filter_fields
      filtered = false
      @filter_fields.each do |field_name, field_values|
        value = event.get(field_name)
        if field_values.empty?
          filtered = true if value.nil?
        else
          unless value.nil?
            found = false
            Array(field_values).each do |field_value|
              if value == field_value
                found = true
                break
              end
            end
            filtered = true if found == false
          else
            filtered = true
          end
        end
      end
      return if filtered == true
    end
    if (gelf_timestamp = event.get(TIMESTAMP_GELF_FIELD)).is_a?(Numeric)
      event.timestamp = coerce_timestamp(gelf_timestamp)
      event.remove(TIMESTAMP_GELF_FIELD)
    end
    if @remap
      remap_gelf(event)
      return if event.get("message").nil?
    end
    strip_leading_underscore(event) if @strip_leading_underscore
    logger.debug("decode(event)", :event => event.to_hash)
    yield event
  end # decode_gelf

  def remap_gelf(event)
    if event.get("full_message") && !event.get("full_message").empty?
      event.set("message", event.get("full_message").dup)
      event.remove("full_message")
      if event.get("short_message") == event.get("message")
        event.remove("short_message")
      end
    elsif event.get("short_message") && !event.get("short_message").empty?
      event.set("message", event.get("short_message").dup)
      event.remove("short_message")
    end
    if event.get("version")
      event.remove("version")
    end
  end # def remap_gelf

  def strip_leading_underscore(event)
     # Map all '_foo' fields to simply 'foo'
     event.to_hash.keys.each do |key|
       next unless key.is_a?(String)
       next unless key[0,1] == "_"
       key = "_id" if key == "__id" # "_id" is reserved, so set back to "id"
       if key == "_@timestamp"
         event.set(key[1..-1], LogStash::Timestamp.coerce(event.get(key)))
       elsif @ovh_ldp
         event.set(key[1..-1], convert_type_ldp(key,event.get(key))) rescue next
       else
         event.set(key[1..-1], event.get(key)) rescue next
       end
       event.remove(key)
     end
  end # def strip_leading_underscores

  def truncate_string_length(value)
    default_length = (@max_value_size / 4).floor
    begin
      truncate_length = (@max_value_size / (value.bytesize / value.length)).floor - 1
    rescue
      truncate_length = default_length - 1
    else
      if truncate_length >= @max_value_size
        truncate_length = @max_value_size - 1
      elsif truncate_length < default_length
        truncate_length = default_length - 1
      end
    end
    return truncate_length
  end # def truncate_string_length

  def elasticsearch_integrity(data, record)
     logger.debug("begin (elasticsearch_integrity)", :record => record)
     record.keys.each do |key|
       unless @max_field_length == 0
         if key.length > @max_field_length
           unless data.get(key).nil?
             value = data.get(key)
             data.remove(key)
             key = key[0..@max_field_length-1]
             data.set(key, value)
             data.tag("codec_gelf_stripped_field_#{key}")
             logger.info("codec gelf: stripped filed #{key}")
           end
         end
       end
       unless @max_value_size == 0
         unless record.key?(key)
           record[key] = get_size(data.get(key))
         end
         if record[key] >= @max_value_size
           unless data.get(key).nil?
             cutstring = truncate_string_length(data.get(key))
             data.set(key, data.get(key).to_s[0..cutstring])
             data.tag("codec_gelf_value_of_#{key}_stripped")
             logger.info("codec gelf: value of #{key} stripped")
           end
         end
       end
     end
     logger.debug("after (elasticsearch_integrity)", :data => data.to_hash)
  end # def elasticsearch_integrity

  def convert_type_ldp(field, value)
    if field.end_with? *@ovh_ldp_convention
      case field.split("_").last
        when "int", "long"
          value.to_i rescue value
        when "num", "double", "float"
          value.to_f rescue value
        when "bool"
          if value.to_s =~ TRUE_REGEX
            true
          elsif value.to_s.empty? || value.to_s =~ FALSE_REGEX
            false
          else
            value
          end
        when "date"
          LogStash::Timestamp.coerce(value) rescue value
        else
          value
      end
    else
      value
    end
  end # def convert_type_ldp

  def rewrite_ldp(data, type, name, field, value)
    unless name.end_with? *@ovh_ldp_convention
      field="#{field}_#{type}"
      if data.get(field).nil?
        data.set(field, value)
        data.remove(name)
        return field
      end
    else
      if name != field
        if data.get(field).nil?
          data.set(field, value)
          data.remove(name)
          return field
        end
      end
    end
    return name
  end # def rewrite_ldp

  def check_leading_underscore(data,name,field)
    if name != field
      data.remove(name)
    end
  end # def check_leading_underscore

  def is_t(value)
    begin
      if value[10] == "T"
        return true
      end
    rescue
      return false
    end
  end # def is_t

  def add_leading_underscore(field)
    if @add_leading_underscore
      if !field.start_with?('_') and !@ignore_leading_underscore.include?(field)
        field = "_id" if field == "id" # "_id" is reserved, so use "__id"
        return "_#{field}"
      else
        return field
      end
      return field
    end
  end # def add_leading_underscore

  def get_size(value)
    unless @max_metadata_size == 0
      value_size = value.to_s.bytesize
      unless @max_value_size == 0
        if value_size > @max_value_size
          return @max_value_size
        else
          return value_size
        end
      else
        return value_size
      end
    end
    return 0
  end # def get_size

  def flatten_gelf(data,keep_top=true,fields=0,size=0,reached=false,limit=false,looped=0,record={})
    if fields == 0
      top = true
    else
      top = false
    end
    flatten = false
    data.to_hash.keys.each do |key|
      next if record[key]
      name = key
      if top
        field = add_leading_underscore(key)
      else
        field = key
      end
      value = data.get(key)
      value_size = get_size(value)
      if top
        next if field == "tags"
        if !name.is_a?(String)
          name = name.to_s rescue next
          data.remove(key)
          data.set(field, value)
          check_leading_underscore(data,name,field)
        end
        fields += 1
        size += value_size
      end
      if !top && (value.is_a?(String) and !is_t(value))
        record[field] = value_size
        next
      end
      if !@ignore_metadata.include?(name)
        if value.nil?
          data.set(field, nil)
          check_leading_underscore(data,name,field) if top
          record[field] = value_size
        elsif value.is_a?(Hash)
          if fields + value.count <= @max_field or @max_field == 0
            flatten = true
            remove = true
            value.each do |hash_name, hash_value|
              hash_name = hash_name.tr('\[\]','_')
              if data.get("#{field}_#{hash_name}").nil? and ("#{field}_#{hash_name}".length <= @max_field_length || @max_field_length == 0) and (size + get_size(hash_value) <= @max_metadata_size || @max_metadata_size == 0)
                fields += 1
                size += get_size(hash_value)
                data.set("#{field}_#{hash_name}", hash_value)
              else
                limit = true
                remove = false
              end
            end
            if !top and remove
              data.remove(name)
              fields -= 1
              size -= value_size
            elsif !remove or top
              data.set(field, value.to_s)
              check_leading_underscore(data,name,field) if top
              record[field] = value_size
            end
          else
            reached = true
            remove = false
            unless top
              data.set(field, value.to_s)
              record[field] = value_size
            end
          end
          if top
            if !keep_top and remove and ![@ignore_ovh_ldp].include?(name)
              data.remove(field)
              check_leading_underscore(data,name,field)
              fields -= 1
              size -= value_size
            else
              data.set(field, value.to_s)
              check_leading_underscore(data,name,field)
              record[field] = value_size
            end
          end
        elsif value.is_a?(Array)
          if fields + value.count <= @max_field or @max_field == 0
            flatten = true
            remove = true
            index = 1
            value.each do |arr_value|
              if data.get("#{field}_#{index}").nil? and ("#{field}_#{index}".length <= @max_field_length || @max_field_length == 0) and (size + get_size(arr_value) <= @max_metadata_size || @max_metadata_size == 0)
                fields += 1
                size += get_size(arr_value)
                data.set("#{field}_#{index}", arr_value)
              else
                limit = true
                remove = false
              end
              index += 1
            end
            if !top and remove
              data.remove(name)
              fields -= 1
              size -= value_size
            elsif !remove or top
              data.set(field, value.to_s)
              check_leading_underscore(data,name,field) if top
              record[field] = value_size
            end
          else
            reached = true
            remove = false
            unless top
              data.set(field, value.to_s)
              record[field] = value_size
            end
          end
          if top
            if !keep_top and remove and ![@ignore_ovh_ldp].include?(name)
              data.remove(field)
              check_leading_underscore(data,name,field)
              fields -= 1
              size -= value_size
            else
              data.set(field, value.to_s)
              check_leading_underscore(data,name,field)
              record[field] = value_size
            end
          end
        else
          check_leading_underscore(data,name,field) if top
          if value.is_a? Numeric
            if ovh_ldp
              if value.is_a? Float
                rewrite_field = rewrite_ldp(data,"num",name,field,value)
              elsif value.is_a? Integer
                rewrite_field = rewrite_ldp(data,"int",name,field,value)
              else
                rewrite_field = rewrite_ldp(data,"num",name,field,value)
              end
              record[rewrite_field] = 64
            else
              data.set(field, value)
              record[field] = value_size
            end
          elsif value.is_a? Boolean
            if ovh_ldp
              rewrite_field = rewrite_ldp(data,"bool",name,field,value)
              record[rewrite_field] = 8
            else
              data.set(field, value)
              record[field] = value_size
            end
          else
            if ovh_ldp
              if is_t(value)
                begin
                  is_iso = LogStash::Timestamp.parse_iso8601(value)
                rescue
                  data.set(field, value.to_s) rescue nil
                  record[field] = value_size
                else
                  rewrite_field = rewrite_ldp(data,"date",name,field,value)
                  record[rewrite_field] = 64
                end
              else
                data.set(field, value.to_s) rescue nil
                record[field] = value_size
              end
            else
              data.set(field, value.to_s) rescue nil
              record[field] = value_size
            end
          end
        end
      else
        record[field] = value_size
      end
    end
    looped  += 1
    record = flatten_gelf(data,ovh_ldp,keep_top,fields,size,reached,limit,looped,record) if flatten and looped < 100
    if reached
      logger.info("codec gelf: max field reached")
      data.tag("codec_gelf_max_field_reached")
    end
    if limit
      logger.info("codec gelf: limited expansion")
      data.tag("codec_gelf_limited_expansion")
    end
    if looped >= 100
      logger.info("codec gelf: max loop reached")
      logger.info("max loop record:", :record => record)
    end
    return record
  end # def flatten_gelf

  # from_json_parse uses the Event#from_json method to deserialize and directly produce events
  def from_json_parse(json, &block)
    # from_json will always return an array of item.
    # in the context of gelf, the payload should be an array of 1
    LogStash::Event.from_json(json).each { |event| decode_gelf(event, &block) }
    #LogStash::Event.from_json(json).each { |event| event }
  rescue LogStash::Json::ParserError => e
    logger.warn(PARSE_FAILURE_LOG_MESSAGE, :error => e, :data => json)
  end # def from_json_parse

  # legacy_parse uses the LogStash::Json class to deserialize json
  def legacy_parse(json, &block)
    # ignore empty/blank lines which LogStash::Json#load returns as nil
    o = LogStash::Json.load(json)
    decode_gelf(LogStash::Event.new(o), &block) if o
  rescue LogStash::Json::ParserError => e
    logger.warn(PARSE_FAILURE_LOG_MESSAGE, :error => e, :data => json)
  end # def legacy_parse

  # keep compatibility with all v2.x distributions. only in 2.3 will the Event#from_json method be introduced
  # and we need to keep compatibility for all v2 releases.
  alias_method :parse, LogStash::Event.respond_to?(:from_json) ? :from_json_parse : :legacy_parse

end # class LogStash::Codecs::Gelf
