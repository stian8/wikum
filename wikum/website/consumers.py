import re
import json
import random
import logging
from channels import Group
from channels.auth import channel_session, http_session_user, channel_session_user, channel_session_user_from_http
from engine import *
from django.contrib.auth.models import User
from django.utils import timezone
from website.models import Article, Source, CommentRating, CommentAuthor, Permissions
from website.views import recurse_up_post, recurse_down_num_subtree, make_vector, count_article

log = logging.getLogger(__name__)

@channel_session_user_from_http
def ws_connect(message):
    # Extract the article from the message. This expects message.path to be of the
    # form /[article_name]/visualization_flags, and finds Article if the message path is applicable,
    # and if the Article exists. Otherwise, bails (meaning this is a some othersort
    # of websocket). So, this is effectively a version of _get_object_or_404.
    try:
        # message['path'] = /[article_name]/visualization_flags
        article_id, label = message['path'].decode('ascii').strip('/').split('/')
        if label != 'visualization_flags':
            log.debug('invalid ws path=%s', message['path'])
            return
        article = Article.objects.get(id=article_id)
    except ValueError:
        log.debug('invalid ws path=%s', message['path'])
        return
    except Article.DoesNotExist:
        log.debug('ws article does not exist article_id=%s', article_id)
        return

    Group('article-'+str(article_id), channel_layer=message.channel_layer).add(message.reply_channel)

    message.channel_session['article'] = article.id

@channel_session_user
def ws_receive(message):
    # Look up the article from the channel session, bailing if it doesn't exist
    try:
        article_id = message.channel_session['article']
        article = Article.objects.get(id=article_id)
    except KeyError:
        log.debug('no article in channel_session')
        return
    except Article.DoesNotExist:
        log.debug('recieved message, but article does not exist id=%s', article_id)
        return

    # Parse out a article message from the content text, bailing if it doesn't
    # conform to the expected message format.
    try:
        data = json.loads(message['text'])
        # {u'comment': u'UH', u'owner': u'sunnytian', u'csrfmiddlewaretoken': u'1DQOoWSPiC6zWcfCVIfD8YdqTaU1H597', u'type': u'new_node', u'article': u'35'}

    except ValueError:
        log.debug("ws message isn't json text=%s", text)
        return

    if data:
        try:
            user = message.user
            owner = data.get('owner', None)
            if not owner or owner == "None":
                owner = None
            else:
                owner = User.objects.get(username=owner)

            permission = None
            if user.is_authenticated():
                permission = Permissions.objects.filter(user=user, article=article)
                if permission.exists():
                    permission = permission[0]
            if article.access_mode < 2 or (user.is_authenticated() and permission and (permission.access_level < 2)) or user == owner:
                comment = data['comment']
                req_user = message.user if message.user.is_authenticated() else None
                req_username = message.user.username if message.user.is_authenticated() else None
                # if commentauthor for username use it; otherwise create it
                author = CommentAuthor.objects.filter(username=req_username)
                if user.is_anonymous():
                    req_username = "Anonymous"
                    author = CommentAuthor.objects.create(username=req_username, anonymous=True, is_wikum=True)
                else:
                    if author.exists():
                        author = author[0]
                        author.is_wikum = True
                        author.user = user
                    else:
                        # existing user who is not a comment author
                        author = CommentAuthor.objects.create(username=req_username, is_wikum=True, user=user)
                new_id = random_with_N_digits(10)
                new_comment = None
                explanation = ''
                if data['type'] == 'new_node':
                    new_comment = Comment.objects.create(article=article,
                                                         author=author,
                                                         is_replacement=False,
                                                         disqus_id=new_id,
                                                         text=comment,
                                                         summarized=False,
                                                         text_len=len(comment))
                    explanation = 'new comment'
                elif data['type'] == 'reply_comment':
                    id = data['id']
                    c = Comment.objects.get(id=id)
                    new_comment = Comment.objects.create(article=article,
                                                         author=author,
                                                         is_replacement=False,
                                                         reply_to_disqus=c.disqus_id,
                                                         disqus_id=new_id,
                                                         text=comment,
                                                         summarized=False,
                                                         text_len=len(comment),
                                                         import_order=c.import_order)
                    explanation = 'reply to comment'

                new_comment.save()
                action = data['type']
                h = History.objects.create(user=req_user,
                                           article=article,
                                           action=action,
                                           explanation=explanation)

                h.comments.add(new_comment)
                recurse_up_post(new_comment)

                recurse_down_num_subtree(new_comment)

                # make_vector(new_comment, article)
                article.comment_num = article.comment_num + 1
                article.percent_complete = count_article(article)
                article.last_updated = datetime.datetime.now(tz=timezone.utc)

                article.save()
                response_dict = {'comment': comment, 'd_id': new_comment.id, 'author': req_username, 'type': data['type']}
                if data['type'] == 'reply_comment':
                    response_dict['node_id'] = data['node_id']
                Group('article-'+str(article_id), channel_layer=message.channel_layer).send({'text': json.dumps(response_dict)})
            else:
                Group('article-'+str(article_id), channel_layer=message.channel_layer).send({'text': json.dumps({'comment': 'unauthorized'})})
        except Exception, e:
            print e
            return

@channel_session_user
def ws_disconnect(message):
    try:
        article_id = message.channel_session['article']
        article = Article.objects.get(id=article_id)
        Group('article-'+str(article_id), channel_layer=message.channel_layer).discard(message.reply_channel)
    except (KeyError, Article.DoesNotExist):
        pass