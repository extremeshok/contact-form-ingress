<?php
// Sample config overrides for ingress.php
// Copy to config.ingress.php and adjust values. The array is deep-merged into $CFG.
return [
  'secret' => 'CHANGE_ME_LONG_RANDOM',
  'allowed_origins' => ['https://example.com','http://localhost'],
  'accept_payload' => 'both', // 'json' | 'form' | 'both'
  'notify_targets' => 'email', // 'email', 'n8n' or both via CSV

  'email' => [
    'to' => ['you@example.com'],
    'subject_prefix' => 'Example :: New enquiry — ',
  ],

  'smtp' => [
    'host' => 'smtp.example.com',
    'user' => 'you@example.com',
    'pass' => 'APP_PASSWORD',
    'port' => 587,
    'secure' => 'tls', // tls | ssl | none
    'auth' => 'login',
    'helo' => 'example.com',
    'verify_peer' => true,
    'verify_peer_name' => true,
    'allow_self_signed' => false,
  ],

  // Optional JSON forward
  'json_forward_url' => '',
  'json_forward_secret' => '',

  // Optional CAPTCHA
  'captcha' => [
    'enabled'  => false,
    'provider' => 'turnstile',
    'site_key' => '',
    'secret'   => '',
    'min_score'=> 0.5,
    'action'   => 'contact',
    'hostname' => '',
  ],

  // Built-in CAPTCHA (no third-party)
  'builtin_captcha' => [
    'enabled' => false,
    'min' => 1,
    'max' => 9,
    'ops' => ['+'], // or ['+','-']
  ],

  // Optional auto‑reply (courtesy acknowledgement)
  'auto_reply' => [
    'enabled' => false,
    'subject' => 'Thanks — we received your message',
    'from'    => '', // optional override; defaults to SMTP user
  ],

  // Optional email domain policy
  'email_domain_allow' => [], // e.g. ['company.com']
  'email_domain_block' => [], // e.g. ['disposable.tld']

  // Optional keyword denylist
  'keyword_denylist' => [], // e.g. ['viagra','casino','loan']
  'keyword_denylist_fields' => ['message','notes','enquiry','inquiry','description','request','offer'],

  // Optional queue + retention
  'forward_queue_enabled'  => false,
  'forward_queue_on_fail'  => false,
  'queue_flush_on_get'     => false,
  'retention_days'         => 90,
  'forward_retention_days' => 14,
];
