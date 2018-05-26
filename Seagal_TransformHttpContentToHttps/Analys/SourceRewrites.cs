using Seagal_TransformHttpContentToHttps.WPClient.Model;
using Seagal_TransformHttpContentToHttps.WPClient.View;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Seagal_TransformHttpContentToHttps.Core;
using Seagal_TransformHttpContentToHttps.Model;
using System.Net;
using System.Threading.Tasks;

namespace Seagal_TransformHttpContentToHttps.Analys
{
    public class SourceRewrites : ISourceRewrites
    {
        public string Name => "img-src";
        private static Regex UrlHttpRegex = new Regex($"src=[\"'](.+?)[\"'].+?", RegexOptions.Compiled);

        private List<HttpLink> _imageAnalysList = new List<HttpLink>();
        private Serializer _serializer = new Serializer();

        public SourceRewrites(ILoggerFactory loggerFactory)
            : this(loggerFactory.CreateLogger<SourceRewrites>())
        {
        }

        public SourceRewrites(ILogger logger) => Logger = logger ?? throw new ArgumentNullException(nameof(logger));

        private ILogger Logger { get; }

        public void Execute(Context context)
        {
            var clientFactory = context.ServiceProvider.GetService<IWPClientFactory>();
            var settings = context.Settings;

            var time = DateTime.Now.ToString("yyyyMMddHHmmss");
            var pathFail = @"C:\Users\evhop\Dokument\dumps\Https.txt".Replace(".txt", $"_{time}_fail.txt");
            var pathSuccess = @"C:\Users\evhop\Dokument\dumps\Https.txt".Replace(".txt", $"_{time}_success.txt");

            if (File.Exists(pathFail))
            {
                File.Delete(pathFail);
            }

            if (File.Exists(pathSuccess))
            {
                File.Delete(pathSuccess);
            }

            using (var client = clientFactory.CreateClient(settings.DestinationBuildConnectionString()))
            {
                using (var connection = client.CreateConnection())
                {
                    client.GetTableSchema(connection, settings.DestinationDb.Schema);
                    ExecuteTransaction(context, client, connection);
                }
            }
            //Skriv ut filen
            using (var failStream = File.AppendText(pathFail))
            {
                using (var successStream = File.AppendText(pathSuccess))
                {
                    foreach (var x in _imageAnalysList)
                    {
                        var logText = $"{x.SchemaTable}\t{x.Id}\t{x.HttpSource}\t{x.Succeded}";
                        if (x.Succeded == true)
                        {
                            successStream.WriteLine(logText);
                        }
                        else
                        {
                            failStream.WriteLine(logText);
                        }
                    }
                }
            }
        }

        private void ExecuteTransaction(IContext context, IWPClient client, IConnection connection)
        {
            using (var transaction = connection.BeginTransaction())
            {
                IEnumerable<Post> posts;
                IEnumerable<Meta> postMetas;
                IEnumerable<Comment> comments;
                IEnumerable<Meta> commentMetas;
                IEnumerable<User> users;
                IEnumerable<Meta> userMetas;

                try
                {
                    //Hämta länkar
                    posts = client.GetPosts(connection);
                    postMetas = client.GetPostMeta(connection);
                    comments = client.GetComments(connection);
                    commentMetas = client.GetCommentMeta(connection);
                    users = client.GetUsers(connection);
                    userMetas = client.GetUserMeta(connection);

                    //Avsluta transactionen
                    transaction.Commit();
                }
                catch (Exception e)
                {
                    Console.Write(e.Message);
                    transaction.Rollback();
                    throw;
                }

                if (posts.Any())
                {
                    GetHttpForPost(posts);
                }
                if (postMetas.Any())
                {
                    GetHttpForMeta(postMetas);
                }
                if (comments.Any())
                {
                    GetHttpForComment(comments);
                }
                if (commentMetas.Any())
                {
                    GetHttpForMeta(commentMetas);
                }
                if (users.Any())
                {
                    GetHttpForUser(users);
                }
                if (userMetas.Any())
                {
                    GetHttpForMeta(userMetas);
                }
            }
        }

        private void GetHttpForUser(IEnumerable<User> users)
        {
            foreach (var user in users)
            {
                GetLinkAsync(user.Id, user.SchemaTable, user.Url).Wait();
            }
        }

        private void GetHttpForComment(IEnumerable<Comment> comments)
        {
            foreach (var comment in comments)
            {
                GetLinkAsync(comment.Id, comment.SchemaTable, comment.AuthorUrl).Wait();
                GetLinkAsync(comment.Id, comment.SchemaTable, comment.Content).Wait();
            }
        }

        private void GetHttpForPost(IEnumerable<Post> posts)
        {
            foreach (var post in posts)
            {
                GetLinkAsync(post.Id, post.SchemaTable, post.Content).Wait();
                GetLinkAsync(post.Id, post.SchemaTable, post.ContentFiltered).Wait();
                GetLinkAsync(post.Id, post.SchemaTable, post.Excerpt).Wait();
                //Guid ska inte hämtas då det bara är källor som hämtar in content som behöver skrivas om
            }
        }

        private async Task GetLinkAsync(ulong id, string schemaTable, string content)
        {
            var matches = UrlHttpRegex.Matches(content).ToList();

            if (!matches.Any())
            {
                return;
            }

            // Create a query.   
            IEnumerable<Task<HttpLink>> downloadTasksQuery =
                from match in matches
                where match.Success
                select ProcessURLAsync(match.Groups[1].Value, id, schemaTable);

            // Use ToArray to execute the query and start the download tasks.  
            Task<HttpLink>[] downloadTasks = downloadTasksQuery.ToArray();

            // Await the completion of all the running tasks.  
            HttpLink[] httpLinks = await Task.WhenAll(downloadTasks);
            _imageAnalysList.AddRange(httpLinks.ToList());
        }

        private async Task<HttpLink> ProcessURLAsync(string url, ulong id, string schemaTable)
        {
            var src = url;
            var srcHttps = src.Replace("http", "https");

            var httpLink = new HttpLink
            {
                SchemaTable = schemaTable,
                Id = id,
                HttpSource = src
            };
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(srcHttps);
                request.Method = "HEAD";
                var response = await request.GetResponseAsync();
                httpLink.HttpSource = srcHttps;
                //finns som https
                httpLink.Succeded = true;
            }
            catch (Exception e)
            {
                try
                {
                    var request = (HttpWebRequest)WebRequest.Create(src);
                    request.Method = "HEAD";
                    var response = await request.GetResponseAsync();
                    //finns som http men inte som https
                    httpLink.Succeded = false;
                }
                catch (Exception ex)
                {
                    //finns inte som http
                    httpLink.Succeded = null;
                }
            }
            return httpLink;
        }

        private void GetHttpForMeta(IEnumerable<Meta> postMetas)
        {
            MetaUrlRewriter metaUrlRewriter = new MetaUrlRewriter();
            foreach (var postMeta in postMetas)
            {
                var data = _serializer.Deserialize(postMeta.MetaValue);
                data = metaUrlRewriter.RewriteUrl(data);
                postMeta.MetaValue = _serializer.Serialize(data);
                //TODO lägga till i listan
            }

        }
    }
}
