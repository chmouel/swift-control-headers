=====================
Swift Control headers
=====================

A middleware that selectively allow/disallow to read or write some headers for Swift objects/containers or accounts.

The idea here is to have some information on an container, account or object that only available for the operator and not allowed to be written or read to the user.

Take for example if we want to store some information about `quota` information we obviously want to show the number to the user but not allow to modify.

Using the .reselleradmin feature we would have a user with the reselleradmin right that can upload those information.

For example, let say I have this configuration in my proxy-server.conf::

   header_quota_hard = admin:admin=rw,*=r

It says for the header quota_hard the admin:admin account/user can write to it but all the others can only read.

So now if I have a container called test in the demo account::

   -$ swift -U demo:demo post testdemo

I can add my Meta ::

   -$ swift -U demo:demo post -m "Foo:Blah" testdemo

and it will shows ::

   -$ swift -U demo:demo stat testdemo|grep 'Meta '
    Meta Foo: Blah

but if you try to add the Quota_hard header::

   -$ swift -U demo:demo post -m "Quota-Hard: 400" testdemo
   Container POST failed: [...]  <html><h1>Forbidden</h1><p>Access was denied to this resourc

it will fail.

I am now going to use an admin token to update data to my demo account on containner testdemo::

   -$ curl -X POST -H "X-Container-Meta-Quota-Hard:  400" -H "X-Auth-Token: ${ADMIN_TOKEN}" ${DEMO_URL}/testdemo

and going to try with my user demo if I can see it::

   -$ swift -U demo:demo stat testdemo|grep 'Meta '
   Meta Foo: Blah
   Meta Quota-Hard: 400

.. _`quota`: Some other middleware could takes care of the enforcement.

Quick Install
-------------

1) Install this middleware by checking it out from github and do a::

   python setup.py install

2) Add the control_headers filter in your proxy pipeline like for example in file `proxy-server.conf`::

   [pipeline:main]
   pipeline = catch_errors healthcheck `control_headers` cache ratelimit  authtoken keystoneauth proxy-logging proxy-server

3) Add the configuration of control_headers at the bottom of the file::

   [filter:control_headers]
   use = egg:swift_control_headers#control_headers

4) to the filter section add now your configuration for each headers the format is :

   header_`the_header` = acct_user_or_*=right

The header is one you specify without the X-Meta the acct/user needs to be specified with acct:user
