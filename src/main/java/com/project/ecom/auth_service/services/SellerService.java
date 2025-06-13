package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.exceptions.RegistrationReqNotFoundException;
import com.project.ecom.auth_service.exceptions.RoleNotFoundException;
import com.project.ecom.auth_service.exceptions.UserNotFoundException;
import com.project.ecom.auth_service.models.ApprovalStatus;
import com.project.ecom.auth_service.models.Role;
import com.project.ecom.auth_service.models.SellerRegistrationRequest;
import com.project.ecom.auth_service.models.User;
import com.project.ecom.auth_service.repositories.IRoleRepository;
import com.project.ecom.auth_service.repositories.ISellerRegistrationRequestRepository;
import com.project.ecom.auth_service.repositories.IUserRepository;
import com.project.ecom.auth_service.utils.JwtUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

@Service
public class SellerService implements ISellerService {
    private final IUserRepository userRepo;
    private final ISellerRegistrationRequestRepository sellerRegistrationRequestRepo;
    private final IRoleRepository roleRepo;

    @Autowired
    public SellerService(IUserRepository userRepo, ISellerRegistrationRequestRepository sellerRegistrationRequestRepo, IRoleRepository roleRepo) {
        this.userRepo = userRepo;
        this.sellerRegistrationRequestRepo = sellerRegistrationRequestRepo;
        this.roleRepo = roleRepo;
    }

    @Override
    public SellerRegistrationRequest registerAsSeller(String panNumber, String gstRegNumber, String accessToken) throws ParseException {
        Map<String, Object> claims = JwtUtil.getClaims(accessToken);
        String email = (String) claims.get("sub");
        User user = this.userRepo.findByEmail(email).orElseThrow(() -> new UserNotFoundException(email));
        Optional<SellerRegistrationRequest> reqByUser = this.sellerRegistrationRequestRepo.findByUserEmail(email);
        SellerRegistrationRequest registrationRequest;
        if (reqByUser.isPresent()) {
            registrationRequest = reqByUser.get();
            return registrationRequest;
        }
        // create a new request
        registrationRequest = new SellerRegistrationRequest();
        registrationRequest.setUser(user);
        registrationRequest.setPanNumber(panNumber);
        registrationRequest.setGstRegNumber(gstRegNumber);
        registrationRequest.setApprovalStatus(ApprovalStatus.PENDING);
        return this.sellerRegistrationRequestRepo.save(registrationRequest);
    }

    @Override
    @Transactional
    public SellerRegistrationRequest updateRequestStatus(Long reqId, ApprovalStatus approvalStatus) {
        SellerRegistrationRequest sellerRegistrationRequest = this.sellerRegistrationRequestRepo.findById(reqId).orElseThrow(() -> new RegistrationReqNotFoundException(reqId));
        sellerRegistrationRequest.setApprovalStatus(approvalStatus);
        if (approvalStatus == ApprovalStatus.APPROVED) {
            // adding role "SELLER" to the user
            Role role = this.roleRepo.findByNameIgnoreCase("seller").orElseThrow(() -> new RoleNotFoundException("seller"));
            User user = sellerRegistrationRequest.getUser();
            if (user.getRoles() == null) user.setRoles(new ArrayList<>());
            user.getRoles().add(role);
            this.userRepo.save(user);
        }
        return this.sellerRegistrationRequestRepo.save(sellerRegistrationRequest);
    }
}
