package com.tubebreakup.authorization.model.userToken;

import com.fasterxml.jackson.databind.ser.FilterProvider;

public interface ExpandedToken {
    public FilterProvider getFilterProvider();
}
