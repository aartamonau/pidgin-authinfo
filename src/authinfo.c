/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */

#define PURPLE_PLUGINS

#include <string.h>
#include <glib.h>

#include <core.h>
#include <debug.h>
#include <plugin.h>
#include <version.h>
#include <account.h>

#include <authinfo.h>

#include "config.h"

#define PLUGIN_ID "core-authinfo"
#define CACHE_TTL 10

struct plugin_data_t {
    struct authinfo_data_t *password_data;
    uint drop_password_data_timer;
    GList *managed_accounts;
};

static const char *get_protocol(const char *protocol_id);

static gboolean fill_password_data(struct plugin_data_t *plugin_data);
static void rearm_drop_password_data_timer(struct plugin_data_t *plugin_data);
static void cancel_drop_password_data_timer(struct plugin_data_t *plugin_data);

static struct authinfo_data_t *read_password_data();
static gboolean query(const struct plugin_data_t *plugin_data,
                      const PurpleAccount *account,
                      struct authinfo_parse_entry_t *entry);
static void set_password(PurpleAccount *account,
                         struct authinfo_parse_entry_t *entry);
static void do_set_password(PurpleAccount *account, const char *password);
static void maybe_wipe_password(PurpleAccount *account,
                                struct plugin_data_t *plugin_data);

static void on_account_connecting(PurpleAccount *account,
                                  struct plugin_data_t *plugin_data);
static void on_account_signed_on(PurpleAccount *account,
                                 struct plugin_data_t *plugin_data);
static void on_account_signed_off(PurpleAccount *account,
                                  struct plugin_data_t *plugin_data);
static gboolean on_drop_password_data_timer(struct plugin_data_t *plugin_data);

static gboolean
plugin_load(PurplePlugin *plugin)
{
    enum authinfo_result_t ret;
    struct plugin_data_t *plugin_data;

    ret = authinfo_init();
    if (ret != AUTHINFO_OK) {
        purple_debug_fatal(PLUGIN_ID, "Failed to initialize authinfo: %s\n",
                           authinfo_strerror(ret));
        return FALSE;
    }

    plugin_data = malloc(sizeof(*plugin_data));
    if (plugin_data == NULL) {
        purple_debug_fatal(PLUGIN_ID, "Failed to allocate plugin specific data\n");
        return FALSE;
    }

    plugin_data->password_data = NULL;
    plugin_data->drop_password_data_timer = 0;
    plugin_data->managed_accounts = NULL;

    plugin->extra = plugin_data;

    if (!fill_password_data(plugin_data)) {
        free(plugin_data);
        return FALSE;
    }

    GList *accounts;

    for (accounts = purple_accounts_get_all();
         accounts != NULL;
         accounts = accounts->next) {
        struct authinfo_parse_entry_t entry;
        PurpleAccount *account = accounts->data;

        if (query(plugin_data, account, &entry)) {
            do_set_password(account, "dummy password");
            authinfo_parse_entry_free(&entry);
        }
    }

    (void) purple_signal_connect(purple_accounts_get_handle(), "account-connecting",
                                 plugin, PURPLE_CALLBACK(on_account_connecting),
                                 plugin_data);

    (void) purple_signal_connect(purple_accounts_get_handle(), "account-signed-on",
                                 plugin, PURPLE_CALLBACK(on_account_signed_on),
                                 plugin_data);

    (void) purple_signal_connect(purple_accounts_get_handle(), "account-signed-off",
                                 plugin, PURPLE_CALLBACK(on_account_signed_off),
                                 plugin_data);

    return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
    struct plugin_data_t *plugin_data = plugin->extra;

    cancel_drop_password_data_timer(plugin_data);

    if (plugin_data->password_data != NULL) {
        authinfo_data_free(plugin_data->password_data);
    }

    g_list_free(plugin_data->managed_accounts);

    free(plugin_data);

    return TRUE;
}

static void
init_plugin(PurplePlugin *plugin) {
}

static PurplePluginInfo info = {
    .magic = PURPLE_PLUGIN_MAGIC,
    .major_version = PURPLE_MAJOR_VERSION,
    .minor_version = PURPLE_MINOR_VERSION,
    .type = PURPLE_PLUGIN_STANDARD,
    .ui_requirement = NULL,
    .flags = 0,
    .dependencies = NULL,
    .priority = PURPLE_PRIORITY_DEFAULT,
    .id = PLUGIN_ID,
    .name = "authinfo",
    .version = PACKAGE_VERSION,
    .summary = "Read account passwords from authinfo file",
    .description = "Read account passwords from authinfo file",
    .author = "Aliaksey Artamonau <aliaksiej.artamonau@gmail.com>",
    .homepage = "https://github.com/aartamonau/pidgin-authinfo",
    .load = plugin_load,
    .unload = plugin_unload,
    .destroy = NULL,
    .ui_info = NULL,
    .extra_info = NULL,
    .prefs_info = NULL,
    .actions = NULL,
    ._purple_reserved1 = NULL,
    ._purple_reserved2 = NULL,
    ._purple_reserved3 = NULL,
    ._purple_reserved4 = NULL,
};

PURPLE_INIT_PLUGIN(authinfo, init_plugin, info)

/* internal functions */
#define PURPLE_PREFIX "prpl-"

static const char *
get_protocol(const char *protocol_id)
{
    size_t n = strlen(PURPLE_PREFIX);

    if (strncmp(protocol_id, PURPLE_PREFIX, n) == 0) {
        return protocol_id + n;
    }

    return protocol_id;
}

static struct authinfo_data_t *
read_password_data()
{
    enum authinfo_result_t ret;

    char *file;
    struct authinfo_data_t *data;

    ret = authinfo_find_file(&file);
    if (ret != AUTHINFO_OK) {
        purple_debug_fatal(PLUGIN_ID, "Failed to find password file: %s\n",
                           authinfo_strerror(ret));
        return NULL;
    }

    ret = authinfo_data_from_file(file, &data);
    if (ret != AUTHINFO_OK) {
        purple_debug_fatal(PLUGIN_ID, "Failed to read password file: %s\n",
                           authinfo_strerror(ret));
        free(file);
        return NULL;
    }

    free(file);
    return data;
}

static gboolean
query(const struct plugin_data_t *plugin_data, const PurpleAccount *account,
      struct authinfo_parse_entry_t *entry)
{
    enum authinfo_result_t ret;

    const char *username = purple_account_get_username(account);
    const char *protocol_id = purple_account_get_protocol_id(account);
    const char *protocol = get_protocol(protocol_id);

    const struct authinfo_data_t *password_data = plugin_data->password_data;

    g_assert(password_data != NULL);

    ret = authinfo_simple_query(password_data, NULL,
                                protocol, username, entry, NULL);
    if (ret != AUTHINFO_OK && ret != AUTHINFO_ENOMATCH) {
        purple_debug_fatal(PLUGIN_ID,
                           "Failure while searching for password (%s:%s): %s\n",
                           protocol, username, authinfo_strerror(ret));
        return FALSE;
    }

    if (ret == AUTHINFO_OK && entry->password != NULL) {
        purple_debug_info(PLUGIN_ID, "Found password for %s:%s\n",
                          protocol, username);
        return TRUE;
    }

    purple_debug_info(PLUGIN_ID, "Couldn't find a password for %s:%s\n",
                      protocol, username);

    if (ret == AUTHINFO_OK) {
        authinfo_parse_entry_free(entry);
    }

    return FALSE;
}

static void
set_password(PurpleAccount *account, struct authinfo_parse_entry_t *entry)
{
    const char *password;
    enum authinfo_result_t ret;

    const char *username = purple_account_get_username(account);
    const char *protocol_id = purple_account_get_protocol_id(account);
    const char *protocol = get_protocol(protocol_id);

    ret = authinfo_password_extract(entry->password, &password);
    if (ret != AUTHINFO_OK) {
        purple_debug_fatal("Couldn't get password for %s:%s: %s\n",
                           protocol, username, authinfo_strerror(ret));
    } else {
        do_set_password(account, password);
        purple_debug_info("Set password for %s:%s", protocol, username);
    }
}

static void
do_set_password(PurpleAccount *account, const char *password)
{
    purple_account_set_remember_password(account, FALSE);
    purple_account_set_password(account, password);
}

static gboolean
fill_password_data(struct plugin_data_t *plugin_data)
{
    if (plugin_data->password_data == NULL) {
        struct authinfo_data_t *password_data = read_password_data();

        if (password_data == NULL) {
            return FALSE;
        }

        plugin_data->password_data = password_data;
    }

    rearm_drop_password_data_timer(plugin_data);

    return TRUE;
}

static void
rearm_drop_password_data_timer(struct plugin_data_t *plugin_data)
{
    cancel_drop_password_data_timer(plugin_data);
    plugin_data->drop_password_data_timer =
        g_timeout_add_seconds(CACHE_TTL,
                              (GSourceFunc) on_drop_password_data_timer,
                              plugin_data);
}

static void
cancel_drop_password_data_timer(struct plugin_data_t *plugin_data)
{
    if (plugin_data->drop_password_data_timer) {
        g_source_remove(plugin_data->drop_password_data_timer);
        plugin_data->drop_password_data_timer = 0;
    }
}

static void
maybe_wipe_password(PurpleAccount *account, struct plugin_data_t *plugin_data)
{
    GList *item = g_list_find(plugin_data->managed_accounts, account);
    if (item) {
        do_set_password(account, "dummy password");
        plugin_data->managed_accounts =
            g_list_delete_link(plugin_data->managed_accounts, item);
    }
}

static void
on_account_connecting(PurpleAccount *account,
                      struct plugin_data_t *plugin_data)
{

    if (!fill_password_data(plugin_data)) {
        return;
    }

    struct authinfo_parse_entry_t entry;
    if (query(plugin_data, account, &entry)) {
        set_password(account, &entry);
        authinfo_parse_entry_free(&entry);

        plugin_data->managed_accounts =
            g_list_append(plugin_data->managed_accounts, account);
    }
}

static void
on_account_signed_on(PurpleAccount *account,
                     struct plugin_data_t *plugin_data)
{
    maybe_wipe_password(account, plugin_data);
}

static void
on_account_signed_off(PurpleAccount *account,
                      struct plugin_data_t *plugin_data)
{
    maybe_wipe_password(account, plugin_data);
}

static gboolean
on_drop_password_data_timer(struct plugin_data_t *plugin_data)
{
    g_assert(plugin_data->password_data != NULL);
    authinfo_data_free(plugin_data->password_data);

    plugin_data->password_data = NULL;
    plugin_data->drop_password_data_timer = 0;

    return FALSE;
}
