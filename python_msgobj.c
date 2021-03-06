/* $Id: python_iface.c,v 1.1 2009/12/09 09:28:26 root Exp $
 *
 * Copyright (C) 2009 Sippy Software, Inc., http://www.sippysoft.com
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
*/

#include "../../action.h"
#include "../../mem/mem.h"
#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../data_lump.h"
#include "../../dset.h"
#include "../../parser/msg_parser.h"
#include "../dialog/dlg_load.h"
#include "../tm/tm_load.h"

#include <Python.h>
#include "structmember.h"

#ifndef Py_TYPE
#define Py_TYPE(ob)               (((PyObject*)(ob))->ob_type)
#endif

//Dialog binding struct
extern struct dlg_binds *lb_dlg_binds;
extern struct tm_binds python_tmb;

//OpenSIPS route return code
extern int return_code;

typedef struct {
    PyObject_HEAD
    struct sip_msg *msg;
} msgobject;

static PyTypeObject MSGtype;

#define is_msgobject(v)         ((v)->ob_type == &MSGtype)

msgobject *
newmsgobject(struct sip_msg *msg)
{
    msgobject *msgp;

    msgp = PyObject_New(msgobject, &MSGtype);
    if (msgp == NULL)
        return NULL;

    msgp->msg = msg;
    return msgp;
}

void
msg_invalidate(msgobject *self)
{

    self->msg = NULL;
}

static void
msg_dealloc(msgobject *msgp)
{

    PyObject_Del(msgp);
}

static PyObject *
msg_copy(msgobject *self)
{
    msgobject *msgp;

    if ((msgp = newmsgobject(self->msg)) == NULL)
        return NULL;

    return (PyObject *)msgp;
}

static PyObject *
msg_rewrite_ruri(msgobject *self, PyObject *args)
{
    char *ruri;
    struct action act;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if ((self->msg->first_line).type != SIP_REQUEST) {
        PyErr_SetString(PyExc_RuntimeError, "Not a request message - "
          "rewrite is not possible.\n");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "s:rewrite_ruri", &ruri))
        return NULL;

    memset(&act, '\0', sizeof(act));

    act.type = SET_URI_T;
    act.elem[0].type = STR_ST;
    act.elem[0].u.s.s = ruri;
    act.elem[0].u.s.len = strlen(ruri);

    if (do_action(&act, self->msg) < 0) {
        LM_ERR("Error in do_action\n");
        PyErr_SetString(PyExc_RuntimeError, "Error in do_action\n");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
msg_set_dst_uri(msgobject *self, PyObject *args)
{
    str ruri;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if ((self->msg->first_line).type != SIP_REQUEST) {
        PyErr_SetString(PyExc_RuntimeError, "Not a request message - "
          "set destination is not possible.\n");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "s:set_dst_uri", &ruri.s))
        return NULL;

    ruri.len = strlen(ruri.s);

    if (set_dst_uri(self->msg, &ruri) < 0) {
        LM_ERR("Error in set_dst_uri\n");
        PyErr_SetString(PyExc_RuntimeError, "Error in set_dst_uri\n");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

/*---------------------------- HEADERS MANIPULATION ------------------------------*/

/* add_hf_helper function copied from sipmsgops module */
static int add_hf_helper(struct sip_msg* msg, str *str1, str *str2,
		gparam_p hfval, int mode, gparam_p hfanc)
{
	struct lump* anchor;
	struct hdr_field *hf;
	char *s;
	int len;
	str s0;

	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("error while parsing message\n");
		return -1;
	}
	
	hf = 0;
	if(hfanc!=NULL) {
		for (hf=msg->headers; hf; hf=hf->next) {
			if(hfanc->type==GPARAM_TYPE_INT)
			{
				if (hfanc->v.ival!=hf->type)
					continue;
			} else {
				if (hf->type!=HDR_OTHER_T)
					continue;
				if (hf->name.len!=hfanc->v.sval.len)
					continue;
				if (strncasecmp(hf->name.s,hfanc->v.sval.s,hf->name.len)!=0)
					continue;
			}
			break;
		}
	}

	if(mode == 0) { /* append */
		if(hf==0) { /* after last header */
			anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0, 0);
		} else { /* after hf */
			anchor = anchor_lump(msg, hf->name.s + hf->len - msg->buf, 0, 0);
		}
	} else { /* insert */
		if(hf==0) { /* before first header */
			anchor = anchor_lump(msg, msg->headers->name.s - msg->buf, 0, 0);
		} else { /* before hf */
			anchor = anchor_lump(msg, hf->name.s - msg->buf, 0, 0);
		}
	}

	if(anchor == 0) {
		LM_ERR("can't get anchor\n");
		return -1;
	}

	if(str1) {
		s0 = *str1;
	} else {
		if(hfval) {
			if(fixup_get_svalue(msg, hfval, &s0)!=0)
			{
				LM_ERR("cannot print the format\n");
				return -1;
			}
		} else {
			s0.len = 0;
			s0.s   = 0;
		}
	}
		
	len=s0.len;
	if (str2) len+= str2->len + REQ_LINE(msg).uri.len;

	s = (char*)pkg_malloc(len);
	if (!s) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memcpy(s, s0.s, s0.len);
	if (str2) {
		memcpy(s+str1->len, REQ_LINE(msg).uri.s, REQ_LINE(msg).uri.len);
		memcpy(s+str1->len+REQ_LINE(msg).uri.len, str2->s, str2->len );
	}

	if (insert_new_lump_before(anchor, s, len, 0) == 0) {
		LM_ERR("can't insert lump\n");
		pkg_free(s);
		return -1;
	}
	return 0;
}

static PyObject *
msg_appendHeader(msgobject *self, PyObject *args)
{
    char tmp[200];
    void *hdr;
    int ret;
    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "s:appendHeader", (char**)&hdr))
        return NULL;
    if (fixup_spve_null(&hdr, 1) != 0) {
        snprintf(tmp, sizeof(tmp), "Invalid header value %s", hdr);
        PyErr_SetString(PyExc_RuntimeError, tmp);
        return NULL;
    }
    ret = add_hf_helper(self->msg, 0, 0, (gparam_p)hdr, 0, 0);
    pkg_free(hdr);
    if (ret == 0) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject *
msg_getHeader(msgobject *self, PyObject *args)
{
    struct hdr_field *hf;
    str hname, *hbody;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "s:getHeader", &hname.s))
        return NULL;
    hname.len = strlen(hname.s);

    parse_headers(self->msg, ~0, 0);
    hbody = NULL;
    for (hf = self->msg->headers; hf != NULL; hf = hf->next) {
        if (hname.len == hf->name.len &&
          strncasecmp(hname.s, hf->name.s, hname.len) == 0) {
            hbody = &(hf->body);
            break;
        }
    }

    if (hbody == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return PyString_FromStringAndSize(hbody->s, hbody->len);
}

static PyObject *
msg_get_pv(msgobject *self, PyObject *args)
{
    str pvname;
    pv_spec_t pv_spec; 
    pv_value_t pv_val;
    char tmp[200];
    int avp_id;
    int_str id_val;
    struct usr_avp *avp;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "s:get_pv", &pvname.s))
        return NULL;
    pvname.len = strlen(pvname.s);
    if (pv_parse_spec(&pvname, &pv_spec)==0 || pv_spec.type==PVT_NULL) {
            snprintf(tmp, sizeof(tmp), "Invalid PV name %s", pvname.s);
            PyErr_SetString(PyExc_RuntimeError, tmp);
            return NULL;
    } 
    
    if (pv_get_spec_value( self->msg, (pv_spec_p) &pv_spec, &pv_val)!=0) {
        snprintf(tmp, sizeof(tmp), "Failed to get pv value for %s", pvname.s);
        PyErr_SetString(PyExc_RuntimeError, tmp);
        return NULL;
    }
    if (pv_val.flags & PV_VAL_INT) {
        return PyLong_FromLong(pv_val.ri);
    }
    else if (pv_val.flags & PV_VAL_STR) {
        return PyString_FromStringAndSize(pv_val.rs.s, pv_val.rs.len);
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
msg_set_pv(msgobject *self, PyObject *args)
{
    str pvname, value;
    pv_spec_t pv_spec; 
    pv_value_t pv_val;
    char tmp[200];

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "ss:set_pv", &pvname.s, &value.s))
        return NULL;
    pvname.len = strlen(pvname.s);
    value.len = strlen(value.s);
    if (pv_parse_spec(&pvname, &pv_spec)==0 || pv_spec.type==PVT_NULL) {
            snprintf(tmp, sizeof(tmp), "Invalid PV name %s", pvname.s);
            PyErr_SetString(PyExc_RuntimeError, tmp);
            return NULL;
    }
    if (pv_spec.type == PVT_AVP) {
        get_avp_id(&pvname); // Force the creation of AVP in shared memory (extra mode)
    } 
    pv_val.flags = PV_VAL_STR;
    pv_val.rs = value;
    if (pv_set_value( self->msg, (pv_spec_p) &pv_spec, 0, &pv_val)!=0) {
        snprintf(tmp, sizeof(tmp), "Failed to set pv value for %s", pvname.s);
        PyErr_SetString(PyExc_RuntimeError, tmp);
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

/*
static PyObject *
msg_set_pv_int(msgobject *self, PyObject *args)
{
    str pvname;
    long int value;
    pv_spec_t pv_spec; 
    pv_value_t pv_val;
    char tmp[200];

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "sl:set_pv", &pvname.s, &value))
        return NULL;
    pvname.len = strlen(pvname.s);
    if (pv_parse_spec(&pvname, &pv_spec)==0 || pv_spec.type==PVT_NULL) {
            snprintf(tmp, sizeof(tmp), "Invalid PV name %s", pvname.s);
            PyErr_SetString(PyExc_RuntimeError, tmp);
            return NULL;
    } 
    pv_val.flags = PV_TYPE_INT & PV_VAL_INT;
    pv_val.ri = value;
    if (pv_set_value( self->msg, (pv_spec_p) &pv_spec, 0, &pv_val)!=0) {
        snprintf(tmp, sizeof(tmp), "Failed to set pv value for %s", pvname.s);
        PyErr_SetString(PyExc_RuntimeError, tmp);
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}
*/

static PyObject *
msg_delete_avp(msgobject *self, PyObject *args)
{
    str avp_name;
    int delete_all, avp_id;
    char tmp[200];

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "si:delete_avp", &avp_name.s, &delete_all))
        return NULL;
    avp_name.len = strlen(avp_name.s);
    avp_id = get_avp_id(&avp_name);
    if (avp_id < 0) {
        snprintf(tmp, sizeof(tmp), "Cannot find avp with name %s", avp_name.s);
        PyErr_SetString(PyExc_RuntimeError, tmp);
        return NULL;
    }
    destroy_avps(0, avp_id, delete_all);
    
    Py_INCREF(Py_None);
    return Py_None;
}

/**
 * Run a routing block
 * Return: False if the execution of routing script should be stopped
 *         True otherwise
 * NOTE: unluckily, we cannot return the returned value of the executed block because the 'run_top_route' function doesn't return it to us 
 */
static PyObject *
msg_run_script_route(msgobject *self, PyObject *args)
{
    char *route_name;
    int route_idx, ret;
    char tmp[200];
    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "s:run_route", &route_name)) {
        PyErr_SetString(PyExc_RuntimeError, "python module: msg_run_script_route: Unable to parse param name");
        return NULL;
    }
    route_idx = get_script_route_ID_by_name(route_name, rlist, RT_NO);
    if (route_idx == -1) {
        snprintf(tmp, sizeof(tmp), "Cannot find route with name %s", route_name);
        PyErr_SetString(PyExc_RuntimeError, tmp);
        return NULL;
    }
    ret = run_top_route( rlist[route_idx].a, self->msg );
    if (ret& ( ACT_FL_DROP | ACT_FL_EXIT) ) {
       /* drop the action */
       LM_DBG("script route %s drops routing "
               "by %d\n", rlist[route_idx].name, ret);
       Py_RETURN_FALSE; 
    }
    Py_RETURN_TRUE;
}

static PyObject*
msg_set_dlg_profile(msgobject *self, PyObject *args)
{
    str profile_name;
    str value;
    int auto_create = 0;
    struct dlg_profile_table * profile;
    char tmp[500];

    if (lb_dlg_binds == NULL) {
        printf("lb_dlg_binds is NULL");
        fflush(stderr);
        fflush(stdout);
        PyErr_SetString(PyExc_RuntimeError, "Dialog module is not loaded");
        return NULL;
    }
    /* create dialog if it is not already created*/
    if (lb_dlg_binds->create_dlg( self->msg, 0)!=1 ) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to create dialog");
            return NULL;
    }
    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }
    if(!PyArg_ParseTuple(args, "ss|i:set_dlg_profile", &profile_name.s, &value.s, &auto_create)) {
        PyErr_SetString(PyExc_RuntimeError, "python msg_set_dlg_profile: unable to parse params");
        return NULL;
    }
    profile_name.len = strlen(profile_name.s);
    value.len = strlen(value.s);
    profile = lb_dlg_binds->search_profile(&profile_name);
    if (profile==NULL ) {
        if (auto_create) {
            if ( lb_dlg_binds->add_profiles(profile_name.s, 1) != 0 ) {
                PyErr_SetString(PyExc_RuntimeError, "Unable to create new profile");
                return NULL;
            }
            // Search again for the newly created profile
            profile = lb_dlg_binds->search_profile(&profile_name);
            if (!profile) {
                PyErr_SetString(PyExc_RuntimeError, "BUG: cannot find newly created profile");
                return NULL;
            }
        }
        else {
            snprintf(tmp, sizeof(tmp), "Profile <%s> is not definied", profile_name.s);
            PyErr_SetString(PyExc_RuntimeError, tmp);
             return NULL;
        }
    }
    if (profile->has_value) {
        if ( lb_dlg_binds->set_profile( self->msg, &value, profile) < 0 ) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to set dialog's profile");
            return NULL;
        }
    } else {
         if ( lb_dlg_binds->set_profile( self->msg, NULL, profile) < 0 ) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to set dialog's profile");
            return NULL;
         }
    }
    Py_RETURN_TRUE;
}

static PyObject*
msg_get_dlg_profile_size(msgobject *self, PyObject *args)
{
    str profile_name;
    str value;
    struct dlg_profile_table * profile;
    char tmp[500];
    int ret = 0;

    if (lb_dlg_binds == NULL) {
        printf("lb_dlg_binds is NULL");
        fflush(stderr);
        fflush(stdout);
        PyErr_SetString(PyExc_RuntimeError, "Dialog module is not loaded");
        return NULL;
    }
    
    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }
    value.s = NULL;
    if(!PyArg_ParseTuple(args, "s|s:set_dlg_profile", &profile_name.s, &value.s))
        return NULL;
    profile_name.len = strlen(profile_name.s);
    if (value.s) {
        value.len = strlen(value.s);
    }
    // Search for the profile
    profile = lb_dlg_binds->search_profile(&profile_name);
    if (profile==NULL ) {
        snprintf(tmp, sizeof(tmp), "Profile <%s> is not definied", profile_name.s);
        PyErr_SetString(PyExc_RuntimeError, tmp);
        return NULL;
    }
    if (value.s) {
        ret = lb_dlg_binds->get_profile_size(profile, &value);
    }
    else {
        ret = lb_dlg_binds->get_profile_size(profile, NULL);
    }
    return PyInt_FromLong(ret);
}

static PyObject*
msg_store_dlg_value(msgobject *self, PyObject *args)
{
    str name;
    str value;
    struct dlg_cell *dlg;
    int ret = 0;

    if (lb_dlg_binds == NULL) {
        printf("lb_dlg_binds is NULL");
        fflush(stderr);
        fflush(stdout);
        PyErr_SetString(PyExc_RuntimeError, "Dialog module is not loaded");
        return NULL;
    }
    
    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }
    if(!PyArg_ParseTuple(args, "ss:store_dlg_value", &name.s, &value.s))
        return NULL;
    name.len = strlen(name.s);
    value.len = strlen(value.s);
                    
    if ( (dlg=lb_dlg_binds->get_dlg())==NULL ) {
        Py_RETURN_FALSE;
    }
    if ( lb_dlg_binds->store_dlg_value(dlg, &name, &value) == 0 ) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject*
msg_fetch_dlg_value(msgobject *self, PyObject *args)
{
    str name;
    str value;
    struct dlg_cell *dlg;
    int ret = 0;

    if (lb_dlg_binds == NULL) {
        printf("lb_dlg_binds is NULL");
        fflush(stderr);
        fflush(stdout);
        PyErr_SetString(PyExc_RuntimeError, "Dialog module is not loaded");
        return NULL;
    }
    
    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }
    if(!PyArg_ParseTuple(args, "s:fetch_dlg_value", &name.s))
        return NULL;
    name.len = strlen(name.s);
                    
    if ( (dlg=lb_dlg_binds->get_dlg())==NULL ) {
        Py_RETURN_FALSE;
    }
    if ( lb_dlg_binds->fetch_dlg_value(dlg, &name, &value, 0) == 0 ) {
        return PyString_FromStringAndSize(value.s, value.len);
    }
    Py_RETURN_NONE;
}

static PyObject*
msg_append_branch(msgobject *self, PyObject *args)
{
    str uri, d_uri;
    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if(!PyArg_ParseTuple(args, "sz:append_branch", &uri.s, &d_uri.s))
        return NULL;
    uri.len = strlen(uri.s);
    if (d_uri.s) {
        d_uri.len = strlen(d_uri.s);
    }
    else {
        d_uri.len = 0;
    }
   if ( append_branch(self->msg, &uri, &d_uri, NULL, 0, 0, NULL) == -1) {
        Py_RETURN_FALSE;
    }
    Py_RETURN_TRUE;
}

/* TM MODULE FUNCTIONS */
static PyObject*
msg_t_reply(msgobject *self, PyObject *args)
{
    str reply_text;
    int reply_code;
    int ret;
    char tmp[500];
    
    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "is:t_reply", &reply_code, &reply_text.s)) {
        return NULL;
    }
    reply_text.len = strlen(reply_text.s);
    ret =  python_tmb.t_reply(self->msg, reply_code, &reply_text);
    return PyLong_FromLong(ret);
}

/* This function msg_call_function is dangerous to call. The problem is that each 
 * fixup function of functions exported by OpenSIPS modules handles behaves differently
 * regarding who free the memory. Some fixup functions free the memory pointed to by 
 * its parameters (e.g alias_db module) while other don't. 
 * In routing script, there is no problem because the fixup functions are called only ONE time
 * and memory malloc'ed by these fixup functions is never freed. However, the msg_call_function
 * can be called many time and if we don't handle this correctly, there will be memory leak
*/

/*
static PyObject *
msg_call_function(msgobject *self, PyObject *args)
{
    int i, rval;
    char *fname, *arg1, *arg2, *arg3;
    cmd_export_t *fexport;
    struct action *act;
    action_elem_t elems[MAX_ACTION_ELEMS];

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    i = PySequence_Size(args);
    if (i < 1 || i > 4) {
        PyErr_SetString(PyExc_RuntimeError, "call_function() should " \
          "have from 1 to 4 arguments");
        return NULL;
    }
    
    if(!PyArg_ParseTuple(args, "s|sss:call_function", &fname, &arg1, &arg2, &arg3))
        return NULL;

    fexport = find_cmd_export_t(fname, i - 1, 0);
    if (fexport == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "no such function");
        return NULL;
    }

    elems[0].type = CMD_ST;
    elems[0].u.data = fexport;
    elems[1].type = STRING_ST;
    elems[1].u.data = arg1;
    elems[2].type = STRING_ST;
    elems[2].u.data = arg2;
    elems[3].type = STRING_ST;
    elems[3].u.data = arg3;
    act = mk_action(MODULE_T, i, elems, 0);

    if (act == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
          "action structure could not be created");
        return NULL;
    }

    if (fexport->fixup != NULL) {
        if (i >= 4) {
            rval = fexport->fixup(&(act->elem[3].u.data), 3);
            if (rval < 0) {
                PyErr_SetString(PyExc_RuntimeError, "Error in fixup (3)");
                return NULL;
            }
            act->elem[3].type = MODFIXUP_ST;
        }
        if (i >= 3) {
            rval = fexport->fixup(&(act->elem[2].u.data), 2);
            if (rval < 0) {
                PyErr_SetString(PyExc_RuntimeError, "Error in fixup (2)");
                return NULL;
            }
            act->elem[2].type = MODFIXUP_ST;
        }
        if (i >= 2) {
            rval = fexport->fixup(&(act->elem[1].u.data), 1);
            if (rval < 0) {
                PyErr_SetString(PyExc_RuntimeError, "Error in fixup (1)");
                return NULL;
            }
            act->elem[1].type = MODFIXUP_ST;
        }
        if (i == 1) {
            rval = fexport->fixup(0, 0);
            if (rval < 0) {
                PyErr_SetString(PyExc_RuntimeError, "Error in fixup (0)");
                return NULL;
            }
        }
    }
    rval = do_action(act, self->msg);
    if ((act->elem[3].type == MODFIXUP_ST) && (act->elem[3].u.data)) {
       pkg_free(act->elem[3].u.data);
    }

    if ((act->elem[2].type == MODFIXUP_ST) && (act->elem[2].u.data)) {
       pkg_free(act->elem[2].u.data);
    }

    if ((act->elem[1].type == MODFIXUP_ST) && (act->elem[1].u.data)) {
        pkg_free(act->elem[1].u.data);
    }

    pkg_free(act);
    return PyInt_FromLong(rval);
}
*/

PyDoc_STRVAR(copy_doc,
"copy() -> msg object\n\
\n\
Return a copy (``clone'') of the msg object.");

static PyMethodDef msg_methods[] = {
    {"copy",          (PyCFunction)msg_copy,          METH_NOARGS,  copy_doc},
    {"rewrite_ruri",  (PyCFunction)msg_rewrite_ruri,  METH_VARARGS,
      "Rewrite Request-URI."},
    {"set_dst_uri",   (PyCFunction)msg_set_dst_uri,   METH_VARARGS,
      "Set destination URI."},
    {"header_get",     (PyCFunction)msg_getHeader,     METH_VARARGS,
      "Get SIP header field by name."},
    {"header_append",     (PyCFunction)msg_appendHeader,     METH_VARARGS,
      "Add SIP header field by name."},
    {"run_script_route", (PyCFunction)msg_run_script_route, METH_VARARGS,
      "Run a routing block from python script."},
    {"get_pv", (PyCFunction)msg_get_pv, METH_VARARGS,
      "Get value of a pseudo variable."},
    {"set_pv", (PyCFunction)msg_set_pv, METH_VARARGS,
      "Set value of a pseudo variable."},
/*
    {"set_pv_int", (PyCFunction)msg_set_pv_int, METH_VARARGS,
      "Set value of a pseudo variable with an integer value."},
*/
    {"delete_avp", (PyCFunction)msg_delete_avp, METH_VARARGS,
      "Delete AVPs by name."},
    {"set_dlg_profile",   (PyCFunction)msg_set_dlg_profile,   METH_VARARGS,
      "Set dialog profile with value."},
    {"get_dlg_profile_size",   (PyCFunction)msg_get_dlg_profile_size,   METH_VARARGS,
      "get the size of a dialog profile."},
    {"set_dlg_value",   (PyCFunction)msg_store_dlg_value,   METH_VARARGS,
      "Set a value for a dialog."},
    {"get_dlg_value",   (PyCFunction)msg_fetch_dlg_value,   METH_VARARGS,
      "get a value of a variable in a dialog."},
    {"append_branch",   (PyCFunction)msg_append_branch,   METH_VARARGS,
      "Append a branch to the current transaction."},
    /* ------------- TM Module Functions ---------- */
    {"t_reply",   (PyCFunction)msg_t_reply,   METH_VARARGS,
      "Send a reply using TM module."},
    {NULL, NULL, 0, NULL}                              /* sentinel */
};

static PyObject *
msg_getType(msgobject *self, PyObject *unused)
{
    const char *rval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    switch ((self->msg->first_line).type) {
    case SIP_REQUEST:
       rval = "SIP_REQUEST";
       break;

    case SIP_REPLY:
       rval = "SIP_REPLY";
       break;

    default:
       /* Shouldn't happen */
       abort();
    }
    return PyString_FromString(rval);
}

static PyObject *
msg_getMethod(msgobject *self, PyObject *unused)
{
    str *rval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if ((self->msg->first_line).type != SIP_REQUEST) {
        PyErr_SetString(PyExc_RuntimeError, "Not a request message - "
          "no method available.\n");
        return NULL;
    }
    rval = &((self->msg->first_line).u.request.method);
    return PyString_FromStringAndSize(rval->s, rval->len);
}

static PyObject *
msg_getStatus(msgobject *self, PyObject *unused)
{
    str *rval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if ((self->msg->first_line).type != SIP_REPLY) {
        PyErr_SetString(PyExc_RuntimeError, "Not a non-reply message - "
          "no status available.\n");
        return NULL;
    }

    rval = &((self->msg->first_line).u.reply.status);
    return PyString_FromStringAndSize(rval->s, rval->len);
}

static PyObject *
msg_getRURI(msgobject *self, PyObject *unused)
{
    str *rval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    if ((self->msg->first_line).type != SIP_REQUEST) {
        PyErr_SetString(PyExc_RuntimeError, "Not a request message - "
          "RURI is not available.\n");
        return NULL;
    }

    rval = &((self->msg->first_line).u.request.uri);
    return PyString_FromStringAndSize(rval->s, rval->len);
}

static PyObject *
msg_get_src_address(msgobject *self, PyObject *unused)
{
    PyObject *src_ip, *src_port, *pyRval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    src_ip = PyString_FromString(ip_addr2a(&self->msg->rcv.src_ip));
    if (src_ip == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    src_port = PyInt_FromLong(self->msg->rcv.src_port);
    if (src_port == NULL) {
        Py_DECREF(src_ip);
        Py_INCREF(Py_None);
        return Py_None;
    }

    pyRval = PyTuple_Pack(2, src_ip, src_port);
    Py_DECREF(src_ip);
    Py_DECREF(src_port);
    if (pyRval == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return pyRval;
}

static PyObject *
msg_get_dst_address(msgobject *self, PyObject *unused)
{
    PyObject *dst_ip, *dst_port, *pyRval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        return NULL;
    }

    dst_ip = PyString_FromString(ip_addr2a(&self->msg->rcv.dst_ip));
    if (dst_ip == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    dst_port = PyInt_FromLong(self->msg->rcv.dst_port);
    if (dst_port == NULL) {
        Py_DECREF(dst_ip);
        Py_INCREF(Py_None);
        return Py_None;
    }

    pyRval = PyTuple_Pack(2, dst_ip, dst_port);
    Py_DECREF(dst_ip);
    Py_DECREF(dst_port);
    if (pyRval == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return pyRval;
}

static PyGetSetDef msg_getseters[] = {
    {"Type",
     (getter)msg_getType, NULL, NULL,
     "Get message type - \"SIP_REQUEST\" or \"SIP_REPLY\"."},
    {"Method",
     (getter)msg_getMethod, NULL, NULL,
     "Get SIP method name."},
    {"Status",
     (getter)msg_getStatus, NULL, NULL,
     "Get SIP status code string."},
    {"RURI",
     (getter)msg_getRURI, NULL, NULL,
     "Get SIP Request-URI."},
    {"src_address",
     (getter)msg_get_src_address, NULL, NULL,
     "Get (IP, port) tuple representing source address of the message."},
    {"dst_address",
     (getter)msg_get_dst_address, NULL, NULL,
     "Get (IP, port) tuple representing destination address of the message."},
    {NULL, NULL, NULL, NULL, NULL}  /* Sentinel */
};

static PyTypeObject MSGtype = {
#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,                        /*ob_size*/
#endif
    "OpenSIPS.msg",           /*tp_name*/
    sizeof(msgobject),        /*tp_size*/
    0,                        /*tp_itemsize*/
    /* methods */
    (destructor)msg_dealloc,  /*tp_dealloc*/
    0,                        /*tp_print*/
    0,                        /*tp_getattr*/
    0,                        /*tp_setattr*/
    0,                        /*tp_compare*/
    0,                        /*tp_repr*/
    0,                        /*tp_as_number*/
    0,                        /*tp_as_sequence*/
    0,                        /*tp_as_mapping*/
    0,                        /*tp_hash*/
    0,                        /*tp_call*/
    0,                        /*tp_str*/
    0,                        /*tp_getattro*/
    0,                        /*tp_setattro*/
    0,                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,       /*tp_flags*/
    0,                        /*tp_doc*/
    0,                        /*tp_traverse*/
    0,                        /*tp_clear*/
    0,                        /*tp_richcompare*/
    0,                        /*tp_weaklistoffset*/
    0,                        /*tp_iter*/
    0,                        /*tp_iternext*/
    msg_methods,              /*tp_methods*/
    0,                        /*tp_members*/
    msg_getseters,            /*tp_getset*/
};

int
python_msgobj_init(void)
{

    Py_TYPE(&MSGtype) = &PyType_Type;
    if (PyType_Ready(&MSGtype) < 0)
        return -1;
    return 0;
}
