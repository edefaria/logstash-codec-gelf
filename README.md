# Logstash gelf codec Plugin

This is a codec plugin for [Logstash](https://github.com/elastic/logstash) to parse gelf messages.

It requires Logstash >= 2.4.0.

Tested on Logstash 5.6 to 7.x on:
* logstash-input-tcp
* logstash-input-kafka
* logstash-output-kafka
* logstash-output-tcp

This plugin is develop for gelf usage on logstash environment for [OVH Logs Data Platform](https://docs.ovh.com/fr/logs-data-platform/).
A lot of check is made in this plugin for generating [gelf protocol](https://docs.graylog.org/en/latest/pages/gelf.html) and to be used on multi user oriented environment.

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Configuration

**custom_fields**: an array for adding custom field mappings.

e.g.
```
custom_fields => ['foo_field', 'some_value']
```
```
custom_fields => ['foo_field', 'some_value', 'second_field', 'second_value']
```

**delimiter**: Support Gelf TCP frame delimiter (use nul framing with Gelf TCP).
No framing is loaded by default (for UDP, kafka, ...).

Only nul, tab, newline delimiter is supported currently.

e.g. nul delimiter (for TCP):
```
delimiter => "\x00"
```
e.g. newline delimiter:
```
delimiter => "\n"
```

Use this codec in any configuration of logstash input or output plugins.
Here's some examples.

[Logstash Input TCP](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-tcp.html)
```
input {
  tcp {
    codec => gelf { delimiter => "\x00" }
    port => 12201
  }
}
```

[Logstash Input Kafka](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-kafka.html)
```
input {
  kafka {
    topic_id => "my_topic"
    group_id => "logstash-test"
    codec => gelf {
      filter_fields => {
        'foo_field' => 'bar_value'
        'some_field' => ['value1','value2','value3']
      }
    }
    bootstrap_servers => "127.0.0.1:9092"
    auto_offset_reset => "latest"
}
```

[Logstash Output TCP](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-tcp.html) with TLS
```
output {
  tcp {
    host => "localhost"
    port => 12201
    codec => gelf {
      delimiter => "\x00"
      custom_fields => { 'foo_field' => 'some_value }
    }
    ssl_enable => true
  }
}
```

[Logstash Output kafka](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-kafka.html)
```
output {
  kafka {
    topic_id => "my_topic"
    codec => gelf { custom_fields => ['foo_field', 'some_value'] }
    bootstrap_servers => "127.0.0.1:9092"
    compression_type => "snappy"
  }
}
```

## Documentation

Logstash provides infrastructure to automatically generate documentation for this plugin. We use the asciidoc format to write documentation so any comments in the source code will be first converted into asciidoc and then into html. All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

- For formatting code or config example, you can use the asciidoc `[source,ruby]` directive
- For more asciidoc formatting tips, see the excellent reference here https://github.com/elastic/docs#asciidoc-guide

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed.

- Create a new plugin or clone and existing from the GitHub [logstash-plugins](https://github.com/logstash-plugins) organization. We also provide [example plugins](https://github.com/logstash-plugins?query=example).

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-awesome", :path => "/your/local/logstash-filter-awesome"
```
- Install plugin
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {awesome {}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-filter-awesome.gemspec
```
- Install the plugin from the Logstash home
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.
