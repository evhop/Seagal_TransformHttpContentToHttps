using System.Collections.Generic;
using Seagal_TransformHttpContentToHttps.WPClient.View;

namespace Seagal_TransformHttpContentToHttps.WPClient.Model
{
    public interface IUserRepository
    {
        IEnumerable<User> GetUsers( IConnection connection );
        void UpdateUsers( IEnumerable<User> users );
        void UpdateUsers( IConnection connection, IEnumerable<User> users);
    }
}