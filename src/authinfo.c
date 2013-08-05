/* -*- mode: c; c-basic-offset: 4; tab-width: 4; ; indent-tabs-mode: nil; -*- */

#define PURPLE_PLUGINS

#include <glib.h>

#include <debug.h>
#include <plugin.h>
#include <version.h>
#include <account.h>

#include <authinfo.h>

#define PLUGIN_ID "core-authinfo"

static gboolean
plugin_load(PurplePlugin *plugin)
{
    GList *accounts;

    for (accounts = purple_accounts_get_all();
         accounts != NULL;
         accounts = accounts->next) {
        PurpleAccount *account = accounts->data;

        purple_debug_info(PLUGIN_ID,
                          "Found account: username %s, alias %s, password %s, "
                          "user_info %s, protocol_id %s",
                          account->username, account->alias, account->password,
                          account->user_info, account->protocol_id);
    }

    return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
    return TRUE;
}

static void init_plugin(PurplePlugin *plugin) {
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
