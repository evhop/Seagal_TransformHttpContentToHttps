﻿using MySql.Data.MySqlClient;
using System;
using Seagal_TransformHttpContentToHttps.WPClient.Model;

namespace Seagal_TransformHttpContentToHttps.WPClient
{
    public class Transaction : ITransaction
    {
        private MySqlTransaction _transaction;

        public Transaction( MySqlTransaction transaction ) => _transaction = transaction ?? throw new ArgumentNullException( nameof( transaction ) );

        public void Commit() => _transaction.Commit();

        public void Dispose()
        {
            if( _transaction != null )
            {
                _transaction.Dispose();
                _transaction = null;
            }
        }

        public void Rollback() => _transaction.Rollback();
    }
}
