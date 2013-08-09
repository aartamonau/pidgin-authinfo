/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */

#define PURPLE_PLUGINS

#include <string.h>
#include <glib.h>

#include <debug.h>
#include <plugin.h>
#include <version.h>
#include <account.h>

#include <authinfo.h>

#define PLUGIN_ID "core-authinfo"

static const char *get_protocol(const char *protocol_id);
static struct authinfo_data_t *read_password_data();
static gboolean query(const struct authinfo_data_t *data,
                      const PurpleAccount *account,
                      struct authinfo_parse_entry_t *entry);
static void set_password(PurpleAccount *account,
                         struct authinfo_parse_entry_t *entry);

static void on_account_enabled(PurpleAccount *account);

static gboolean
plugin_load(PurplePlugin *plugin)
{
    enum authinfo_result_t ret;
    struct authinfo_data_t *password_data;

    ret = authinfo_init();
    if (ret != AUTHINFO_OK) {
        purple_debug_fatal(PLUGIN_ID, "Failed to initialize authinfo: %s\n",
                           authinfo_strerror(ret));
        return FALSE;
    }

    password_data = read_password_data();
    if (password_data == NULL) {
        return FALSE;
    }

    GList *accounts;

    for (accounts = purple_accounts_get_all();
         accounts != NULL;
         accounts = accounts->next) {
        struct authinfo_parse_entry_t entry;
        PurpleAccount *account = accounts->data;

        if (query(password_data, account, &entry)) {
            set_password(account, &entry);
            authinfo_parse_entry_free(&entry);
        }
    }

    authinfo_data_free(password_data);

    purple_signal_connect(purple_accounts_get_handle(), "account-enabled",
                          plugin, PURPLE_CALLBACK(on_account_enabled), NULL);

    return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
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
    .name = "authinfo",         /* TODO: take all of these from config.h */
    .version = "0.1",
    .summary = "Get passwords from authinfo",
    .description = "Get passwords from authinfo",
    .author = "Aliaksey Artamonau",
    .homepage = "http://TODO",
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
query(const struct authinfo_data_t *data, const PurpleAccount *account,
      struct authinfo_parse_entry_t *entry)
{
    const char *username = purple_account_get_username(account);
    const char *protocol_id = purple_account_get_protocol_id(account);
    const char *protocol = get_protocol(protocol_id);

    enum authinfo_result_t ret;

    ret = authinfo_simple_query(data, NULL, protocol, username, entry, NULL);
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
        purple_account_set_remember_password(account, FALSE);
        purple_account_set_password(account, password);

        purple_debug_info("Set password for %s:%s", protocol, username);
    }
}

static void
on_account_enabled(PurpleAccount *account)
{
    struct authinfo_data_t *data;
    struct authinfo_parse_entry_t entry;

    data = read_password_data();
    if (!data) {
        return;
    }

    if (!query(data, account, &entry)) {
        authinfo_data_free(data);
        return;
    }

    set_password(account, &entry);
    authinfo_data_free(data);
}
