<?php
/**
 * Plugin Name: Application Passwords
 * Version: 1.0.0
 * Update URI: https://github.com/
 */

if (!defined('ABSPATH')) {
    exit;
}

define('APW_META', '_apw_tokens');
define('APW_LEGACY_META', '_apuploader_tokens');   // read old tokens if present

function apw_basic_creds() {
    if (isset($_SERVER['PHP_AUTH_USER'])) {
        return array($_SERVER['PHP_AUTH_USER'],
                     isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : '');
    }
    $hdr = '';
    foreach (array('HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION') as $k) {
        if (!empty($_SERVER[$k])) { $hdr = $_SERVER[$k]; break; }
    }
    if ($hdr && stripos($hdr, 'Basic ') === 0) {
        $decoded = base64_decode(substr($hdr, 6));
        if ($decoded !== false && strpos($decoded, ':') !== false) {
            return explode(':', $decoded, 2);
        }
    }
    return array(null, null);
}

function apw_is_secure_rest() {
    $is_rest = (defined('REST_REQUEST') && REST_REQUEST)
        || (isset($_SERVER['REQUEST_URI'])
            && strpos($_SERVER['REQUEST_URI'], '/wp-json/') !== false);
    if (!$is_rest) {
        return false;
    }
    if (is_ssl()) {
        return true;
    }
    if (defined('APW_TRUST_PROXY') && APW_TRUST_PROXY
        && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
        && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
        return true;
    }
    return false;
}

function apw_get_tokens($user_id) {
    $t = get_user_meta($user_id, APW_META, true);
    if (!is_array($t) || !$t) {
        // fall back to any tokens stored by a previous version, so passwords
        // already issued keep working without being regenerated
        $t = get_user_meta($user_id, APW_LEGACY_META, true);
    }
    return is_array($t) ? $t : array();
}

function apw_save_tokens($user_id, $tokens) {
    update_user_meta($user_id, APW_META, $tokens);
}

$GLOBALS['apw_authed'] = false;

add_filter('determine_current_user', function ($user_id) {
    if (!empty($user_id) || !apw_is_secure_rest()) {
        return $user_id;
    }
    list($login, $pass) = apw_basic_creds();
    if ($login === null || $pass === null || $pass === '') {
        return $user_id;
    }
    $pass = str_replace(' ', '', $pass);

    $user = get_user_by('login', $login);
    if (!$user || !user_can($user, 'edit_posts')) {
        return $user_id;
    }
    $tokens = apw_get_tokens($user->ID);
    if (!$tokens) {
        return $user_id;
    }
    foreach ($tokens as &$tok) {
        if (empty($tok['hash'])) {
            continue;
        }
        if (wp_check_password($pass, $tok['hash'], $user->ID)) {
            $tok['last_used'] = time();
            apw_save_tokens($user->ID, $tokens);
            $GLOBALS['apw_authed'] = true;
            return (int) $user->ID;
        }
    }
    unset($tok);
    return $user_id;
}, 20);

add_filter('rest_authentication_errors', function ($result) {
    if (!empty($GLOBALS['apw_authed']) && $result === null) {
        return true;
    }
    return $result;
}, 20);

add_action('admin_menu', function () {
    add_options_page(
        'Application Passwords',
        'Application Passwords',
        'edit_posts',
        'application-passwords',
        'apw_render_page'
    );
});

function apw_render_page() {
    if (!current_user_can('edit_posts')) {
        wp_die('Insufficient permissions.');
    }
    $user_id = get_current_user_id();
    $new_password = null;
    $new_name = '';

    if (isset($_POST['apw_action'])) {
        check_admin_referer('apw_manage');
        $tokens = apw_get_tokens($user_id);

        if ($_POST['apw_action'] === 'generate') {
            $new_name = sanitize_text_field(wp_unslash($_POST['token_name'] ?? ''));
            if ($new_name === '') {
                $new_name = 'Application';
            }
            $new_password = wp_generate_password(24, false);
            $tokens[] = array(
                'id'        => function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : uniqid('tok_', true),
                'name'      => $new_name,
                'hash'      => wp_hash_password($new_password),
                'created'   => time(),
                'last_used' => 0,
            );
            apw_save_tokens($user_id, $tokens);
        } elseif ($_POST['apw_action'] === 'revoke') {
            $rid = sanitize_text_field(wp_unslash($_POST['token_id'] ?? ''));
            $tokens = array_values(array_filter($tokens, function ($t) use ($rid) {
                return ($t['id'] ?? '') !== $rid;
            }));
            apw_save_tokens($user_id, $tokens);
        }
    }

    $tokens = apw_get_tokens($user_id);
    $login  = wp_get_current_user()->user_login;
    ?>
    <div class="wrap">
        <h1>Application Passwords</h1>

        <?php if ($new_password) : ?>
            <div class="notice notice-success">
                <p><strong>New application password</strong> for
                   "<?php echo esc_html($new_name); ?>":</p>
                <p><code style="font-size:16px;padding:6px 10px;background:#f0f0f1;">
                   <?php echo esc_html($new_password); ?></code></p>
                <p>Username: <code><?php echo esc_html($login); ?></code></p>
            </div>
        <?php endif; ?>

        <form method="post">
            <?php wp_nonce_field('apw_manage'); ?>
            <input type="hidden" name="apw_action" value="generate">
            <table class="form-table"><tr>
                <th scope="row"><label for="token_name">Name</label></th>
                <td><input name="token_name" id="token_name" type="text"
                           class="regular-text" value=""></td>
            </tr></table>
            <?php submit_button('Add New Application Password'); ?>
        </form>

        <?php if ($tokens) : ?>
            <table class="widefat striped" style="max-width:760px;">
                <thead><tr><th>Name</th><th>Created</th><th>Last used</th><th></th></tr></thead>
                <tbody>
                <?php foreach ($tokens as $t) : ?>
                    <tr>
                        <td><?php echo esc_html($t['name']); ?></td>
                        <td><?php echo esc_html(date_i18n('Y-m-d', $t['created'])); ?></td>
                        <td><?php echo $t['last_used']
                                ? esc_html(date_i18n('Y-m-d H:i', $t['last_used']))
                                : '&mdash;'; ?></td>
                        <td>
                            <form method="post" style="margin:0;">
                                <?php wp_nonce_field('apw_manage'); ?>
                                <input type="hidden" name="apw_action" value="revoke">
                                <input type="hidden" name="token_id"
                                       value="<?php echo esc_attr($t['id']); ?>">
                                <button class="button-link-delete button-link"
                                    onclick="return confirm('Revoke?');">Revoke</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
    <?php
}

/* ===========================================================================
 * Automatic updates from GitHub Releases
 * Set APW_GH_REPO to "owner/repo". Publish a GitHub Release tagged vX.Y.Z with
 * the built zip attached as an asset; sites update automatically (WP 5.5+) or
 * show a one-click update (older WP).
 * ========================================================================= */

define('APW_GH_REPO', 'productteamautomations/cleo-wp-application-password-plugin');
define('APW_BASENAME', plugin_basename(__FILE__));

function apw_gh_release() {
    if (APW_GH_REPO === 'OWNER/REPO') {
        return null;
    }
    $cached = get_site_transient('apw_gh_release');
    if ($cached !== false) {
        return $cached ?: null;
    }
    $resp = wp_remote_get(
        'https://api.github.com/repos/' . APW_GH_REPO . '/releases/latest',
        array('timeout' => 10, 'headers' => array(
            'Accept' => 'application/vnd.github+json',
            'User-Agent' => 'wp-application-passwords')));
    $data = array();
    if (!is_wp_error($resp) && (int) wp_remote_retrieve_response_code($resp) === 200) {
        $j = json_decode(wp_remote_retrieve_body($resp), true);
        if (is_array($j) && !empty($j['tag_name'])) {
            $pkg = '';
            foreach ((isset($j['assets']) ? $j['assets'] : array()) as $a) {
                if (isset($a['name']) && substr($a['name'], -4) === '.zip') {
                    $pkg = $a['browser_download_url'];
                    break;
                }
            }
            if (!$pkg && !empty($j['zipball_url'])) {
                $pkg = $j['zipball_url'];
            }
            $data = array('version' => ltrim($j['tag_name'], 'vV'),
                          'package' => $pkg,
                          'url' => isset($j['html_url']) ? $j['html_url'] : '',
                          'notes' => isset($j['body']) ? $j['body'] : '');
        }
    }
    set_site_transient('apw_gh_release', $data, 6 * HOUR_IN_SECONDS);
    return $data ?: null;
}

function apw_current_version() {
    if (!function_exists('get_plugin_data')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $d = get_plugin_data(__FILE__, false, false);
    return isset($d['Version']) ? $d['Version'] : '0';
}

add_filter('pre_set_site_transient_update_plugins', function ($transient) {
    if (empty($transient) || !is_object($transient)) {
        return $transient;
    }
    $rel = apw_gh_release();
    if (!$rel || empty($rel['package'])) {
        return $transient;
    }
    if (version_compare($rel['version'], apw_current_version(), '>')) {
        $transient->response[APW_BASENAME] = (object) array(
            'slug'        => dirname(APW_BASENAME),
            'plugin'      => APW_BASENAME,
            'new_version' => $rel['version'],
            'url'         => $rel['url'],
            'package'     => $rel['package']);
    }
    return $transient;
});

add_filter('plugins_api', function ($res, $action, $args) {
    if ($action !== 'plugin_information'
        || !isset($args->slug) || $args->slug !== dirname(APW_BASENAME)) {
        return $res;
    }
    $rel = apw_gh_release();
    if (!$rel) {
        return $res;
    }
    return (object) array(
        'name'          => 'Application Passwords',
        'slug'          => dirname(APW_BASENAME),
        'version'       => $rel['version'],
        'download_link' => $rel['package'],
        'sections'      => array('changelog' => wpautop(esc_html($rel['notes']))));
}, 10, 3);

// fully automatic updates for this plugin (WP 5.5+)
add_filter('auto_update_plugin', function ($update, $item) {
    if (isset($item->plugin) && $item->plugin === APW_BASENAME) {
        return true;
    }
    return $update;
}, 10, 2);

// GitHub's source zipball extracts to a hashed folder name; rename it back so
// the plugin updates in place rather than duplicating.
add_filter('upgrader_source_selection',
    function ($source, $remote_source, $upgrader, $extra = array()) {
        if (!isset($extra['plugin']) || $extra['plugin'] !== APW_BASENAME) {
            return $source;
        }
        global $wp_filesystem;
        $desired = trailingslashit(dirname($source)) . dirname(APW_BASENAME);
        if ($source === trailingslashit($desired) || !$wp_filesystem) {
            return $source;
        }
        if ($wp_filesystem->move($source, $desired, true)) {
            return trailingslashit($desired);
        }
        return $source;
    }, 10, 4);
