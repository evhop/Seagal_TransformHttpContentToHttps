using Seagal_TransformHttpContentToHttps.WPClient.View;
using System.Collections.Generic;

namespace Seagal_TransformHttpContentToHttps.WPClient.Model
{
    public interface ICommentRepository
	{
        void UpdateComments(IEnumerable<Comment> comments);
        void UpdateComments(IConnection connection, IEnumerable<Comment> comments);
        IEnumerable<Comment> GetComments(IConnection connection);
    }
}