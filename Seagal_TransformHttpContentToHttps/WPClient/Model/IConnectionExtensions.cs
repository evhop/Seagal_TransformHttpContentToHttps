﻿using MySql.Data.MySqlClient;
using System;

namespace Seagal_TransformHttpContentToHttps.WPClient.Model
{
    public static class IConnectionExtensions
    {
        public static MySqlConnection GetMySqlConnection( this IConnection connection ) => (connection as Connection)?.MySqlConnection ?? throw new ArgumentException( "Must be of type MySqlConnection", nameof( connection ) );
    }
}
